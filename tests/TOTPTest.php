<?php

// MIT LICENSE
//
// $Date: Wed Jul 22 11:43:18 2020 +0200$
// $Rev: v1.0.0-18-ge8d4816$

use PHPUnit\Framework\TestCase;
require __DIR__ . "/../lib/rsct_otp.php";

final class TOTPTest extends TestCase
{
    /**
     * Get a private or protected method for testing/documentation purposes.
     * How to use for MyClass->foo():
     *      $cls = new MyClass();
     *      $foo = PHPUnitUtil::getPrivateMethod($cls, 'foo');
     *      $foo->invoke($cls, $...);
     * @param object $obj The instantiated instance of your class
     * @param string $name The name of your private/protected method
     * @return ReflectionMethod The method you asked for
     */
    private static function getPrivateMethod($obj, $name) {
      $class = new ReflectionClass($obj);
      $method = $class->getMethod($name);
      $method->setAccessible(true);
      return $method;
    }

    private static $token = "082630";

    private static function now() {
        return strtotime("2016-09-23 09:00");
    }

    private static function totp($input = 'JBSWY3DPEHPK3PXP') {
        return new RSCT_OTP\TOTP($input);
    }

    public function testTokenIsNumber(): void
    {
        $this->assertEquals(self::$token, self::totp()->at(self::now()));
    }

    public function testRFCCompatibility(): void
    {
        $totp = self::totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
        $this->assertEquals("050471", $totp->at(1111111111));
        $this->assertEquals("005924", $totp->at(1234567890));
        $this->assertEquals("279037", $totp->at(2000000000));
    }

    public function testVerifyThrowsErrorWithInteger(): void
    {
        $this->expectException(\Exception::class);
        self::totp()->verify(82630, array("at" => self::now()));
    }

    public function testVerifyFailsWithUnpaddedString(): void
    {
        $this->assertNull(
            self::totp()->verify("82630", array("at" => self::now()))
        );
    }

    public function testVerifySucceedes(): void
    {
        $this->assertNotNull(
            self::totp()->verify("082630", array("at" => self::now()))
        );
    }

    public function testRFCCompatibilityCorrect(): void
    {
        $totp = self::totp("wrn3pqx5uqxqvnqr");
        $this->assertNotNull(
            $totp->verify("102705", array("at" => 1297553958))
        );
    }

    public function testRFCCompatibilityFails(): void
    {
        $totp = self::totp("wrn3pqx5uqxqvnqr");
        $this->assertNull(
            $totp->verify("102705", array("at" => self::now()))
        );
    }

    public function testReuseSameTokenFails(): void
    {
        $totp = self::totp();
        $after = $totp->verify("082630", array("at" => self::now()));
        $this->assertNotNull($after);
        $this->assertNull(
            $totp->verify("082630", array("at" => self::now(),
                                          "after" => $after))
        );
    }

    public function testDriftingTimecodesBehind(): void
    {
        $totp = self::totp();
        $method = self::getPrivateMethod($totp, "get_timecodes");
        $this->assertEquals([49154040],
                            $method->invokeArgs($totp, [self::now() + 15, 15, 0]));
        $this->assertEquals([49154039, 49154040],
                            $method->invokeArgs($totp, [self::now(), 15, 0]));
        $this->assertEquals([49154038, 49154039, 49154040],
                            $method->invokeArgs($totp, [self::now(), 40, 0]));
        $this->assertEquals([49154037, 49154038, 49154039, 49154040],
                            $method->invokeArgs($totp, [self::now(), 90, 0]));
    }

    public function testDriftingTimecodesAhead(): void
    {
        $totp = self::totp();
        $method = self::getPrivateMethod($totp, "get_timecodes");
        $this->assertEquals([49154040],
                            $method->invokeArgs($totp, [self::now(), 0, 15]));
        $this->assertEquals([49154040, 49154041],
                            $method->invokeArgs($totp, [self::now() + 15, 0, 15]));
        $this->assertEquals([49154040, 49154041],
                            $method->invokeArgs($totp, [self::now(), 0, 30]));
        $this->assertEquals([49154040, 49154041, 49154042],
                            $method->invokeArgs($totp, [self::now(), 0, 70]));
        $this->assertEquals([49154040, 49154041, 49154042, 49154043],
                            $method->invokeArgs($totp, [self::now(), 0, 90]));
    }

    public function testDriftingTimecodesBeheindAndAhead(): void
    {
        $totp = self::totp();
        $method = self::getPrivateMethod($totp, "get_timecodes");
        $this->assertEquals([49154039, 49154040, 49154041],
                            $method->invokeArgs($totp, [self::now(), 30, 30]));
        $this->assertEquals([49154038, 49154039, 49154040, 49154041, 49154042],
                            $method->invokeArgs($totp, [self::now(), 60, 60]));
    }

    // Tested at 2016-09-23 09:00:00 UTC, and with drift back to 2016-09-23 08:59:45 UTC
    // This would therefore include 2 intervals
    public function testVerifyWithDriftBehind(): void
    {
        $totp = self::totp();
        $token = $totp->at(self::now() - 30);
        $this->assertNotNull(
            $totp->verify($token, array("at" => self::now() - 30, "drift_behind" => 15))
        );
    }

    // Tested at 2016-09-23 09:00:20 UTC, and with drift back to 2016-09-23 09:00:05 UTC
    // This only includes 1 interval, therefore only the current token is valid
    public function testVerifyBehindOutsideDriftRange(): void
    {
        $totp = self::totp();
        $token = $totp->at(self::now() - 30);
        $this->assertNull(
            $totp->verify($token, array("at" => self::now() + 20, "drift_behind" => 15))
        );
    }

    // Tested at 2016-09-23 09:00:20 UTC, and with drift ahead to 2016-09-23 09:00:35 UTC
    // This would therefore include 2 intervals
    public function testVerifyWithDriftAhead(): void
    {
        $totp = self::totp();
        $token = $totp->at(self::now() + 30);
        $this->assertNotNull(
            $totp->verify($token, array("at" => self::now() + 20, "drift_ahead" => 15))
        );
    }

    // Tested at 2016-09-23 09:00:00 UTC, and ahead to 2016-09-23 09:00:15 UTC
    // This only includes 1 interval, therefore only the current token is valid
    public function testVerifyAheadOutsideDriftRange(): void
    {
        $totp = self::totp();
        $token = $totp->at(self::now() + 30);
        $this->assertNull(
            $totp->verify($token, array("at" => self::now(), "drift_ahead" => 15))
        );
    }

    public function testWithDriftAndPreventTokenReuseNotReusedBehind(): void
    {
        $totp = self::totp();
        $token = $totp->at(self::now() - 30);
        $this->assertEquals(
            1474621170,
            $totp->verify($token, array("at" => self::now(), "drift_behind" => 15))
        );
    }

    public function testWithDriftAndPreventTokenReuseReusedBehind(): void
    {
        $totp = self::totp();
        $token = $totp->at(self::now() - 30);
        $this->assertNull(
            $totp->verify($token, array("at" => self::now(), "drift_behind" => 15, "after" => 1474621170))
        );
    }

    public function testWithDriftAndPreventTokenReuseNotReusedAhead(): void
    {
        $totp = self::totp();
        $token = $totp->at(self::now() + 30);
        $this->assertEquals(
            1474621230,
            $totp->verify($token, array("at" => self::now() + 15, "drift_ahead" => 15))
        );
    }

    public function testWithDriftAndPreventTokenReuseReusedAhead(): void
    {
        $totp = self::totp();
        $token = $totp->at(self::now() + 30);
        $this->assertNull(
            $totp->verify($token, array("at" => self::now() + 15, "drift_ahead" => 15, "after" => 1474621230))
        );
    }

    public function testProvisioningURLWithoutIssuer(): void
    {
        $uri = self::totp()->provisioning_uri('mark@percival');
        $this->assertEquals(
            "otpauth://totp/mark@percival?secret=JBSWY3DPEHPK3PXP",
            $uri
        );
    }

    public function testProvisioningURLWithSpaceInName(): void
    {
        $uri = self::totp()->provisioning_uri('mark percival');
        $this->assertEquals(
            "otpauth://totp/mark%20percival?secret=JBSWY3DPEHPK3PXP",
            $uri
        );
    }

    public function testProvisioningURLWithIssuer(): void
    {
        $totp = new RSCT_OTP\TOTP("JBSWY3DPEHPK3PXP", array("issuer" => "FooCo"));
        $uri = $totp->provisioning_uri('mark@percival');
        $this->assertEquals(
            "otpauth://totp/FooCo:mark@percival?secret=JBSWY3DPEHPK3PXP&issuer=FooCo",
            $uri
        );
    }

    public function testProvisioningURLWithIssuerSpaces(): void
    {
        $totp = new RSCT_OTP\TOTP("JBSWY3DPEHPK3PXP", array("issuer" => "Foo Co"));
        $uri = $totp->provisioning_uri('mark@percival');
        $this->assertEquals(
            "otpauth://totp/Foo%20Co:mark@percival?secret=JBSWY3DPEHPK3PXP&issuer=Foo%20Co",
            $uri
        );
    }

    public function testProvisioningURLWithNonDefaultDigits(): void
    {
        $totp = new RSCT_OTP\TOTP("JBSWY3DPEHPK3PXP", array("digits" => 8));
        $uri = $totp->provisioning_uri('mark@percival');
        $this->assertEquals(
            "otpauth://totp/mark@percival?secret=JBSWY3DPEHPK3PXP&digits=8",
            $uri
        );
    }

    public function testProvisioningURLWithInterval(): void
    {
        $totp = new RSCT_OTP\TOTP("JBSWY3DPEHPK3PXP", array("interval" => 60));
        $uri = $totp->provisioning_uri('mark@percival');
        $this->assertEquals(
            "otpauth://totp/mark@percival?secret=JBSWY3DPEHPK3PXP&period=60",
            $uri
        );
    }

    public function testProvisioningURLWithCustomDigest(): void
    {
        $totp = new RSCT_OTP\TOTP("JBSWY3DPEHPK3PXP", array("digest" => "sha256"));
        $uri = $totp->provisioning_uri('mark@percival');
        $this->assertEquals(
            "otpauth://totp/mark@percival?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256",
            $uri
        );
    }

    public function testGoogleAuthenticator(): void
    {
        $totp = new RSCT_OTP\TOTP("wrn3pqx5uqxqvnqr");
        //$this->assertEquals(1, $totp->now());
        $this->assertEquals(102705, $totp->at(1297553958));
    }

    public function testDropbox(): void
    {
        $totp = new RSCT_OTP\TOTP("tjtpqea6a42l56g5eym73go2oa");
        //$this->assertEquals(1, $totp->now());
        $this->assertEquals(747864, $totp->at(1378762454));
    }

}
