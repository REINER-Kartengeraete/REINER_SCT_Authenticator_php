<?php

// MIT LICENSE
//
// $Date: Wed Jul 22 11:43:18 2020 +0200$
// $Rev: v1.0.0-18-ge8d4816$

use PHPUnit\Framework\TestCase;
require __DIR__ . "/../lib/rsct_otp.php";

final class Base32Test extends TestCase
{
    public function testRandomWithoutArgsLength(): void
    {
        $this->assertEquals(32, strlen(RSCT_OTP\Base32::random()));
    }

    public function testRandomWithArgsLength(): void
    {
        $this->assertEquals(64, strlen(RSCT_OTP\Base32::random(40)));
    }

    public function testDecode(): void
    {
        $this->assertEquals(
            'd103f17bd6176727',
            unpack("H*", RSCT_OTP\Base32::decode('2EB7C66WC5TSO'))[1]
        );
        $this->assertEquals(
            'c7b1dc8802fb40111e49',
            unpack("H*", RSCT_OTP\Base32::decode('Y6Y5ZCAC7NABCHSJ'))[1]
        );
    }

    public function testDecodeWithCorruptData(): void
    {
        $this->expectException(RSCT_OTP\Base32ErrorException::class);
        RSCT_OTP\Base32::decode('4BCDEFG234BCDEF1');
    }

    public function testDecodeWithTrailingBits(): void
    {
        // Dropbox style 26 characters (26*5==130 bits or 16.25 bytes, but chopped to 128)
        // Matches the behavior of Google Authenticator, drops extra 2 empty bits
        $this->assertEquals(
            'c567eceae5e0609685931fd9e8060223',
            unpack("H*", RSCT_OTP\Base32::decode('YVT6Z2XF4BQJNBMTD7M6QBQCEM'))[1]
        );
        // For completeness, test all the possibilities allowed by Google Authenticator
        // Drop the incomplete empty extra 4 bits (28*5==140bits or 17.5 bytes, chopped to 136 bits)
        $this->assertEquals(
            'e98d9807766f963fd76be9de3c4e140349',
            unpack("H*", RSCT_OTP\Base32::decode('5GGZQB3WN6LD7V3L5HPDYTQUANEQ'))[1]
        );
    }

    public function testDecodeWithPadding(): void
    {
        $this->assertEquals(
            'd6f8',
            unpack("H*", RSCT_OTP\Base32::decode('234A==='))[1]
        );
    }

    public function testEncode(): void
    {
        $input = pack("H*", '3c204da94294ff82103ee34e96f74b48');
        $this->assertEquals(
            'HQQE3KKCST7YEEB64NHJN52LJA',
            RSCT_OTP\Base32::encode($input)
        );
    }
}
