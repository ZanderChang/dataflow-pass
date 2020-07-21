#include "llvm/Pass.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

#define DEBUG_TYPE "instrument-memory-accesses"

STATISTIC(LoadsInstrumented, "Loads instrumented");
STATISTIC(StoresInstrumented, "Stores instrumented");
STATISTIC(AtomicsInstrumented, "Atomic memory intrinsics instrumented");
STATISTIC(IntrinsicsInstrumented, "Block memory intrinsics instrumented");


namespace {
    class InstrumentMemoryAccesses : public FunctionPass,
    public InstVisitor<InstrumentMemoryAccesses> {
        const DataLayout *TD;
        IRBuilder<> *Builder;

        PointerType *VoidPtrTy;
        IntegerType *SizeTy;

        Function *LoadCheckFunction;
        Function *StoreCheckFunction;

        void instrument(Value *Pointer, Value *AccessSize, Function *Check,
                Instruction &I);

        public:
        static char ID;
        InstrumentMemoryAccesses(): FunctionPass(ID) { }
        virtual bool doInitialization(Module &M);
        virtual bool runOnFunction(Function &F);

        virtual void getAnalysisUsage(AnalysisUsage &AU) const {
            AU.setPreservesCFG();
        }

        virtual StringRef getPassName() const {
            return "InstrumentMemoryAccesses";
        }

        // Visitor methods
        void visitLoadInst(LoadInst &LI);
        void visitStoreInst(StoreInst &SI);
        void visitAtomicCmpXchgInst(AtomicCmpXchgInst &I);
        void visitAtomicRMWInst(AtomicRMWInst &I);
        void visitMemIntrinsic(MemIntrinsic &MI);
    };
} /* namespace */

FunctionPass *createInstrumentMemoryAccessesPass() {
    return new InstrumentMemoryAccesses();
}

bool InstrumentMemoryAccesses::doInitialization(Module &M) {
    Type *VoidTy = Type::getVoidTy(M.getContext());
    VoidPtrTy = Type::getInt8PtrTy(M.getContext());
    SizeTy = IntegerType::getInt64Ty(M.getContext());
    std::vector<Type*> params;
    params.push_back(VoidPtrTy);
    params.push_back(SizeTy);
    params.push_back(VoidPtrTy);
    params.push_back(SizeTy);
    FunctionType *LoadStoreFuncType = FunctionType::get(VoidTy,params,false);
    M.getOrInsertFunction("__loadcheck", LoadStoreFuncType);
    M.getOrInsertFunction("__storecheck", LoadStoreFuncType);
    errs() << "[+] doInitialization done \n";
    return true;
}

bool InstrumentMemoryAccesses::runOnFunction(Function &F) {
    // Check that the load and store check functions are declared.
    LoadCheckFunction = F.getParent()->getFunction("__loadcheck");
    assert(LoadCheckFunction && "__loadcheck function has disappeared!\n");

    StoreCheckFunction = F.getParent()->getFunction("__storecheck");
    assert(StoreCheckFunction && "__storecheck function has disappeared!\n");

    TD = &F.getParent()->getDataLayout();
    IRBuilder<> TheBuilder(F.getContext());
    Builder = &TheBuilder;

    // Visit all of the instructions in the function.
    visit(F);
    return true;
}

//
// Method: instrument()
//
// Description:
//  Insert a call to a run-time check.
//
// Inputs:
//  Pointer    - A value specifying the pointer to be checked.
//  AccessSize - A value specifying the amount of memory, in bytes, that the
//               memory access to check will access.
//  Check      - A pointer to the function that will perform the run-time check.
//  I          - A reference to an instruction before which the call to the
//               check should be inserted.
//
void InstrumentMemoryAccesses::instrument(Value *Pointer, Value *AccessSize,
        Function *Check, Instruction &I) {
    Builder->SetInsertPoint(I.getNextNode()); // behind of I
    Value *VoidPointer = Builder->CreatePointerCast(Pointer, VoidPtrTy);
    // errs() << "instrument instruction " << I << "\n";
    // errs() << "Pointer: " << *Pointer << "\n";
    // errs() << "Size: " << *AccessSize << "\n";
    //errs() << Check->getName();
    //errs() << "load/store/atomic/intrinsics: " << LoadsInstrumented
    //       << "/" << StoresInstrumented
    //       << "/" << AtomicsInstrumented
    //       << "/" << IntrinsicsInstrumented
    //       << " (" << Check->getName() << ")\n";

    Value *RtFile = Builder->CreateGlobalStringPtr("N/A", ".str");
    Value *RtLine = ConstantInt::get(SizeTy, 0);
    if (DILocation *loc = I.getDebugLoc()) {
        //errs() << "Line:" << loc->getLine()
        //    << ", Path:" << loc->getDirectory()
        //    << ", File:" << loc->getFilename() << "\n";
        unsigned Line = loc->getLine();
        RtFile = Builder->CreateGlobalStringPtr(loc->getFilename().str().c_str(), ".str");
        RtLine = ConstantInt::get(SizeTy, Line);
    } else {
        errs() << "[!] No debug info for instruction \""
            << I << "\" you won't get valid file:line messages\n";
    }

    // Create ArrayRef to be passed to Builder->CreateCall.
    Value* args[] = {VoidPointer, AccessSize, RtFile, RtLine};
    CallInst *CI = Builder->CreateCall(Check, args);

    // Copy debug information if it is present.
    if (MDNode *MD = I.getMetadata("dbg")) {
        CI->setMetadata("dbg", MD);
    }

}

void InstrumentMemoryAccesses::visitLoadInst(LoadInst &LI) {
    // Instrument a load instruction with a load check.
    Value *AccessSize = ConstantInt::get(SizeTy,
            TD->getTypeStoreSize(LI.getType()));
    instrument(LI.getPointerOperand(), AccessSize, LoadCheckFunction, LI);
    ++LoadsInstrumented;
}

void InstrumentMemoryAccesses::visitStoreInst(StoreInst &SI) {
    // Instrument a store instruction with a store check.
    uint64_t Bytes = TD->getTypeStoreSize(SI.getValueOperand()->getType());
    Value *AccessSize = ConstantInt::get(SizeTy, Bytes);
    instrument(SI.getPointerOperand(), AccessSize, StoreCheckFunction, SI);
    ++StoresInstrumented;
}

void InstrumentMemoryAccesses::visitAtomicRMWInst(AtomicRMWInst &I) {
    // Instrument an AtomicRMW instruction with a store check.
    Value *AccessSize = ConstantInt::get(SizeTy,
            TD->getTypeStoreSize(I.getType()));
    instrument(I.getPointerOperand(), AccessSize, StoreCheckFunction, I);
    ++AtomicsInstrumented;
}

void InstrumentMemoryAccesses::visitAtomicCmpXchgInst(AtomicCmpXchgInst &I) {
    // Instrument an AtomicCmpXchg instruction with a store check.
    Value *AccessSize = ConstantInt::get(SizeTy,
            TD->getTypeStoreSize(I.getType()));
    instrument(I.getPointerOperand(), AccessSize, StoreCheckFunction, I);
    ++AtomicsInstrumented;
}

void InstrumentMemoryAccesses::visitMemIntrinsic(MemIntrinsic &MI) {
    // Instrument llvm.mem[set|cpy|move].* calls with load/store checks.
    Builder->SetInsertPoint(&MI);
    Value *AccessSize = Builder->CreateIntCast(MI.getLength(), SizeTy,
            /*isSigned=*/false);

    // memcpy and memmove have a source memory area but memset doesn't
    if (MemTransferInst *MTI = dyn_cast<MemTransferInst>(&MI))
        instrument(MTI->getSource(), AccessSize, LoadCheckFunction, MI);
    instrument(MI.getDest(), AccessSize, StoreCheckFunction, MI);
    ++IntrinsicsInstrumented;
}

char InstrumentMemoryAccesses::ID = 0;
namespace llvm {
    FunctionPass *createInstrumentMemoryAccessesPass();
    void initializeInstrumentMemoryAccessesPass(llvm::PassRegistry&);
}
INITIALIZE_PASS(InstrumentMemoryAccesses, "instrument-memory-accesses",
        "Instrument memory accesses", false, false)
//static RegisterPass<InstrumentMemoryAccesses> X("sanitizer", "Memory Sanitizer Pass by Pan");

// Automatically enable the pass.
// http://adriansampson.net/blog/clangpass.html
static void registerPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM) {
  PM.add(new InstrumentMemoryAccesses());
}
static RegisterStandardPasses
  RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible,
                 registerPass);


// instrument instruction   store i32 0, i32* %retval, align 4
// Pointer:   %retval = alloca i32, align 4
// Size: i64 4
// [!] No debug info for instruction "  store i32 0, i32* %retval, align 4" you won't get valid file:line messages

// instrument instruction   call void @llvm.memset.p0i8.i64(i8* align 16 %1, i8 0, i64 256, i1 false), !dbg !13
// Pointer:   %src = alloca [256 x i8], align 16
// Size: i64 256

// instrument instruction   store i8 1, i8* %4, align 16, !dbg !13
// Pointer:   %4 = getelementptr inbounds <{ i8, [255 x i8] }>, <{ i8, [255 x i8] }>* %3, i32 0, i32 0, !dbg !13
// Size: i64 1

// instrument instruction   call void @llvm.memset.p0i8.i64(i8* align 16 %5, i8 0, i64 256, i1 false), !dbg !20
// Pointer:   %dst = alloca [256 x i8], align 16
// Size: i64 256

// instrument instruction   call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 16 %arraydecay1, i8* align 16 %arraydecay2, i64 128, i1 false), !dbg !23
// Pointer:   %src = alloca [256 x i8], align 16
// Size: i64 128
// instrument instruction   call void @llvm.memcpy.p0i8.p0i8.i64(i8* align 16 %arraydecay1, i8* align 16 %arraydecay2, i64 128, i1 false), !dbg !23
// Pointer:   %dst = alloca [256 x i8], align 16
// Size: i64 128

// instrument instruction   %9 = load i8, i8* %arrayidx, align 16, !dbg !26
// Pointer:   %arrayidx = getelementptr inbounds [256 x i8], [256 x i8]* %dst, i64 0, i64 0, !dbg !26
// Size: i64 1
// instrument instruction   store i8 %9, i8* %temp, align 1, !dbg !27
// Pointer:   %temp = alloca i8, align 1
// Size: i64 1

// instrument instruction   %10 = load i8, i8* %arrayidx3, align 1, !dbg !28
// Pointer:   %arrayidx3 = getelementptr inbounds [256 x i8], [256 x i8]* %dst, i64 0, i64 127, !dbg !28
// Size: i64 1
// instrument instruction   store i8 %10, i8* %temp, align 1, !dbg !29
// Pointer:   %temp = alloca i8, align 1
// Size: i64 1

// instrument instruction   %11 = load i8, i8* %arrayidx4, align 16, !dbg !30
// Pointer:   %arrayidx4 = getelementptr inbounds [256 x i8], [256 x i8]* %dst, i64 0, i64 128, !dbg !30
// Size: i64 1
// instrument instruction   store i8 %11, i8* %temp, align 1, !dbg !31
// Pointer:   %temp = alloca i8, align 1
// Size: i64 1
