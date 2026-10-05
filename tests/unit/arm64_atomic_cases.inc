// Original ARM64 LSE min/max instruction and result fixtures.
// All widths and acquire/release variants use X0, X2, [X4].

#ifdef UC_ARM64_ATOMIC_CASE
UC_ARM64_ATOMIC_CASE(SignedMax8Relaxed, SignedMax, 1, 0x38204082)
UC_ARM64_ATOMIC_CASE(SignedMax8Acquire, SignedMax, 1, 0x38a04082)
UC_ARM64_ATOMIC_CASE(SignedMax8Release, SignedMax, 1, 0x38604082)
UC_ARM64_ATOMIC_CASE(SignedMax8AcquireRelease, SignedMax, 1, 0x38e04082)
UC_ARM64_ATOMIC_CASE(SignedMax16Relaxed, SignedMax, 2, 0x78204082)
UC_ARM64_ATOMIC_CASE(SignedMax16Acquire, SignedMax, 2, 0x78a04082)
UC_ARM64_ATOMIC_CASE(SignedMax16Release, SignedMax, 2, 0x78604082)
UC_ARM64_ATOMIC_CASE(SignedMax16AcquireRelease, SignedMax, 2, 0x78e04082)
UC_ARM64_ATOMIC_CASE(SignedMax32Relaxed, SignedMax, 4, 0xb8204082)
UC_ARM64_ATOMIC_CASE(SignedMax32Acquire, SignedMax, 4, 0xb8a04082)
UC_ARM64_ATOMIC_CASE(SignedMax32Release, SignedMax, 4, 0xb8604082)
UC_ARM64_ATOMIC_CASE(SignedMax32AcquireRelease, SignedMax, 4, 0xb8e04082)
UC_ARM64_ATOMIC_CASE(SignedMax64Relaxed, SignedMax, 8, 0xf8204082)
UC_ARM64_ATOMIC_CASE(SignedMax64Acquire, SignedMax, 8, 0xf8a04082)
UC_ARM64_ATOMIC_CASE(SignedMax64Release, SignedMax, 8, 0xf8604082)
UC_ARM64_ATOMIC_CASE(SignedMax64AcquireRelease, SignedMax, 8, 0xf8e04082)
UC_ARM64_ATOMIC_CASE(SignedMin8Relaxed, SignedMin, 1, 0x38205082)
UC_ARM64_ATOMIC_CASE(SignedMin8Acquire, SignedMin, 1, 0x38a05082)
UC_ARM64_ATOMIC_CASE(SignedMin8Release, SignedMin, 1, 0x38605082)
UC_ARM64_ATOMIC_CASE(SignedMin8AcquireRelease, SignedMin, 1, 0x38e05082)
UC_ARM64_ATOMIC_CASE(SignedMin16Relaxed, SignedMin, 2, 0x78205082)
UC_ARM64_ATOMIC_CASE(SignedMin16Acquire, SignedMin, 2, 0x78a05082)
UC_ARM64_ATOMIC_CASE(SignedMin16Release, SignedMin, 2, 0x78605082)
UC_ARM64_ATOMIC_CASE(SignedMin16AcquireRelease, SignedMin, 2, 0x78e05082)
UC_ARM64_ATOMIC_CASE(SignedMin32Relaxed, SignedMin, 4, 0xb8205082)
UC_ARM64_ATOMIC_CASE(SignedMin32Acquire, SignedMin, 4, 0xb8a05082)
UC_ARM64_ATOMIC_CASE(SignedMin32Release, SignedMin, 4, 0xb8605082)
UC_ARM64_ATOMIC_CASE(SignedMin32AcquireRelease, SignedMin, 4, 0xb8e05082)
UC_ARM64_ATOMIC_CASE(SignedMin64Relaxed, SignedMin, 8, 0xf8205082)
UC_ARM64_ATOMIC_CASE(SignedMin64Acquire, SignedMin, 8, 0xf8a05082)
UC_ARM64_ATOMIC_CASE(SignedMin64Release, SignedMin, 8, 0xf8605082)
UC_ARM64_ATOMIC_CASE(SignedMin64AcquireRelease, SignedMin, 8, 0xf8e05082)
UC_ARM64_ATOMIC_CASE(UnsignedMax8Relaxed, UnsignedMax, 1, 0x38206082)
UC_ARM64_ATOMIC_CASE(UnsignedMax8Acquire, UnsignedMax, 1, 0x38a06082)
UC_ARM64_ATOMIC_CASE(UnsignedMax8Release, UnsignedMax, 1, 0x38606082)
UC_ARM64_ATOMIC_CASE(UnsignedMax8AcquireRelease, UnsignedMax, 1, 0x38e06082)
UC_ARM64_ATOMIC_CASE(UnsignedMax16Relaxed, UnsignedMax, 2, 0x78206082)
UC_ARM64_ATOMIC_CASE(UnsignedMax16Acquire, UnsignedMax, 2, 0x78a06082)
UC_ARM64_ATOMIC_CASE(UnsignedMax16Release, UnsignedMax, 2, 0x78606082)
UC_ARM64_ATOMIC_CASE(UnsignedMax16AcquireRelease, UnsignedMax, 2, 0x78e06082)
UC_ARM64_ATOMIC_CASE(UnsignedMax32Relaxed, UnsignedMax, 4, 0xb8206082)
UC_ARM64_ATOMIC_CASE(UnsignedMax32Acquire, UnsignedMax, 4, 0xb8a06082)
UC_ARM64_ATOMIC_CASE(UnsignedMax32Release, UnsignedMax, 4, 0xb8606082)
UC_ARM64_ATOMIC_CASE(UnsignedMax32AcquireRelease, UnsignedMax, 4, 0xb8e06082)
UC_ARM64_ATOMIC_CASE(UnsignedMax64Relaxed, UnsignedMax, 8, 0xf8206082)
UC_ARM64_ATOMIC_CASE(UnsignedMax64Acquire, UnsignedMax, 8, 0xf8a06082)
UC_ARM64_ATOMIC_CASE(UnsignedMax64Release, UnsignedMax, 8, 0xf8606082)
UC_ARM64_ATOMIC_CASE(UnsignedMax64AcquireRelease, UnsignedMax, 8, 0xf8e06082)
UC_ARM64_ATOMIC_CASE(UnsignedMin8Relaxed, UnsignedMin, 1, 0x38207082)
UC_ARM64_ATOMIC_CASE(UnsignedMin8Acquire, UnsignedMin, 1, 0x38a07082)
UC_ARM64_ATOMIC_CASE(UnsignedMin8Release, UnsignedMin, 1, 0x38607082)
UC_ARM64_ATOMIC_CASE(UnsignedMin8AcquireRelease, UnsignedMin, 1, 0x38e07082)
UC_ARM64_ATOMIC_CASE(UnsignedMin16Relaxed, UnsignedMin, 2, 0x78207082)
UC_ARM64_ATOMIC_CASE(UnsignedMin16Acquire, UnsignedMin, 2, 0x78a07082)
UC_ARM64_ATOMIC_CASE(UnsignedMin16Release, UnsignedMin, 2, 0x78607082)
UC_ARM64_ATOMIC_CASE(UnsignedMin16AcquireRelease, UnsignedMin, 2, 0x78e07082)
UC_ARM64_ATOMIC_CASE(UnsignedMin32Relaxed, UnsignedMin, 4, 0xb8207082)
UC_ARM64_ATOMIC_CASE(UnsignedMin32Acquire, UnsignedMin, 4, 0xb8a07082)
UC_ARM64_ATOMIC_CASE(UnsignedMin32Release, UnsignedMin, 4, 0xb8607082)
UC_ARM64_ATOMIC_CASE(UnsignedMin32AcquireRelease, UnsignedMin, 4, 0xb8e07082)
UC_ARM64_ATOMIC_CASE(UnsignedMin64Relaxed, UnsignedMin, 8, 0xf8207082)
UC_ARM64_ATOMIC_CASE(UnsignedMin64Acquire, UnsignedMin, 8, 0xf8a07082)
UC_ARM64_ATOMIC_CASE(UnsignedMin64Release, UnsignedMin, 8, 0xf8607082)
UC_ARM64_ATOMIC_CASE(UnsignedMin64AcquireRelease, UnsignedMin, 8, 0xf8e07082)
#endif
#ifdef UC_ARM64_ATOMIC_KIND
UC_ARM64_ATOMIC_KIND(SignedMin)
UC_ARM64_ATOMIC_KIND(SignedMax)
UC_ARM64_ATOMIC_KIND(UnsignedMin)
UC_ARM64_ATOMIC_KIND(UnsignedMax)
#endif
#ifdef UC_ARM64_ATOMIC_INPUT
UC_ARM64_ATOMIC_INPUT(1, UINT64_C(0x0000000000000010),
                      UINT64_C(0x0123456789abcdef),
                      UINT64_C(0x00000000000000ef),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x00000000000000ef))
UC_ARM64_ATOMIC_INPUT(1, UINT64_C(0xfedcba9876543210),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000000010))
UC_ARM64_ATOMIC_INPUT(1, UINT64_C(0x0000000000000000),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x00000000000000ff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x00000000000000ff))
UC_ARM64_ATOMIC_INPUT(1, UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x00000000000000ff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x00000000000000ff))
UC_ARM64_ATOMIC_INPUT(1, UINT64_C(0x8080808080808080),
                      UINT64_C(0x7f7f7f7f7f7f7f7f),
                      UINT64_C(0x0000000000000080),
                      UINT64_C(0x000000000000007f),
                      UINT64_C(0x000000000000007f),
                      UINT64_C(0x0000000000000080))
UC_ARM64_ATOMIC_INPUT(1, UINT64_C(0xffffffffffffffff),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x00000000000000ff),
                      UINT64_C(0x00000000000000ff),
                      UINT64_C(0x00000000000000ff),
                      UINT64_C(0x00000000000000ff))
UC_ARM64_ATOMIC_INPUT(2, UINT64_C(0x0000000000000010),
                      UINT64_C(0x0123456789abcdef),
                      UINT64_C(0x000000000000cdef),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x000000000000cdef))
UC_ARM64_ATOMIC_INPUT(2, UINT64_C(0xfedcba9876543210),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000003210),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000003210))
UC_ARM64_ATOMIC_INPUT(2, UINT64_C(0x0000000000000000),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x000000000000ffff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x000000000000ffff))
UC_ARM64_ATOMIC_INPUT(2, UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x000000000000ffff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x000000000000ffff))
UC_ARM64_ATOMIC_INPUT(2, UINT64_C(0x8080808080808080),
                      UINT64_C(0x7f7f7f7f7f7f7f7f),
                      UINT64_C(0x0000000000008080),
                      UINT64_C(0x0000000000007f7f),
                      UINT64_C(0x0000000000007f7f),
                      UINT64_C(0x0000000000008080))
UC_ARM64_ATOMIC_INPUT(2, UINT64_C(0xffffffffffffffff),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x000000000000ffff),
                      UINT64_C(0x000000000000ffff),
                      UINT64_C(0x000000000000ffff),
                      UINT64_C(0x000000000000ffff))
UC_ARM64_ATOMIC_INPUT(4, UINT64_C(0x0000000000000010),
                      UINT64_C(0x0123456789abcdef),
                      UINT64_C(0x0000000089abcdef),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000089abcdef))
UC_ARM64_ATOMIC_INPUT(4, UINT64_C(0xfedcba9876543210),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000076543210),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000076543210))
UC_ARM64_ATOMIC_INPUT(4, UINT64_C(0x0000000000000000),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x00000000ffffffff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x00000000ffffffff))
UC_ARM64_ATOMIC_INPUT(4, UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x00000000ffffffff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x00000000ffffffff))
UC_ARM64_ATOMIC_INPUT(4, UINT64_C(0x8080808080808080),
                      UINT64_C(0x7f7f7f7f7f7f7f7f),
                      UINT64_C(0x0000000080808080),
                      UINT64_C(0x000000007f7f7f7f),
                      UINT64_C(0x000000007f7f7f7f),
                      UINT64_C(0x0000000080808080))
UC_ARM64_ATOMIC_INPUT(4, UINT64_C(0xffffffffffffffff),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x00000000ffffffff),
                      UINT64_C(0x00000000ffffffff),
                      UINT64_C(0x00000000ffffffff),
                      UINT64_C(0x00000000ffffffff))
UC_ARM64_ATOMIC_INPUT(8, UINT64_C(0x0000000000000010),
                      UINT64_C(0x0123456789abcdef),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0123456789abcdef),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0123456789abcdef))
UC_ARM64_ATOMIC_INPUT(8, UINT64_C(0xfedcba9876543210),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0xfedcba9876543210),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0x0000000000000010),
                      UINT64_C(0xfedcba9876543210))
UC_ARM64_ATOMIC_INPUT(8, UINT64_C(0x0000000000000000),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0xffffffffffffffff))
UC_ARM64_ATOMIC_INPUT(8, UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0x0000000000000000),
                      UINT64_C(0xffffffffffffffff))
UC_ARM64_ATOMIC_INPUT(8, UINT64_C(0x8080808080808080),
                      UINT64_C(0x7f7f7f7f7f7f7f7f),
                      UINT64_C(0x8080808080808080),
                      UINT64_C(0x7f7f7f7f7f7f7f7f),
                      UINT64_C(0x7f7f7f7f7f7f7f7f),
                      UINT64_C(0x8080808080808080))
UC_ARM64_ATOMIC_INPUT(8, UINT64_C(0xffffffffffffffff),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0xffffffffffffffff),
                      UINT64_C(0xffffffffffffffff))
#endif
#ifdef UC_ARM64_ATOMIC_VALUE
UC_ARM64_ATOMIC_VALUE(DataAddress, 0x3000)
UC_ARM64_ATOMIC_VALUE(InstructionBytes, 4)
UC_ARM64_ATOMIC_VALUE(RegisterMask, 31)
UC_ARM64_ATOMIC_VALUE(ResultRegister, 2)
UC_ARM64_ATOMIC_VALUE(AddressRegister, 4)
UC_ARM64_ATOMIC_VALUE(InitialFlags, 0xb0000000)
#endif
#ifdef UC_ARM64_ATOMIC_WIDE
UC_ARM64_ATOMIC_WIDE(ResultSeed, UINT64_C(0xfedcba98abcdef42))
UC_ARM64_ATOMIC_WIDE(StackSeed, UINT64_C(0x1234567800004000))
#endif
#ifdef UC_ARM64_ATOMIC_TEXT
UC_ARM64_ATOMIC_TEXT(CaseFailure, "%s, input %u, result register %u")
#endif
#ifdef UC_ARM64_ATOMIC_TEST
UC_ARM64_ATOMIC_TEST(test_arm64_atomic_minmax)
#endif
