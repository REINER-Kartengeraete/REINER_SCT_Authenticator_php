<?php

// MIT LICENSE
//
// $Date: Wed Jul 22 11:43:18 2020 +0200$
// $Rev: v1.0.0-18-ge8d4816$

namespace RSCT_OTP;

class OTP
{
    const DEFAULT_DIGITS = 6;
    const DEFAULT_DIGEST = "sha1";

    function __construct($s, $options = []) {
        $this->digits = isset($options["digits"]) ?
            $options["digits"] : self::DEFAULT_DIGITS;
        $this->digest = isset($options["digest"]) ?
            $options["digest"] : self::DEFAULT_DIGEST;
        $this->secret = $s;
    }

    public function generate_otp($input) {
        $hmac = hash_hmac(
            $this->digest,
            $this->int_to_bytestring($input),
            $this->byte_secret(),
            True
        );
        $offset = ord($hmac[-1]) & 0xf;
        $code = (ord($hmac[$offset]) & 0x7f) << 24 |
            (ord($hmac[$offset + 1]) & 0xff) << 16 |
            (ord($hmac[$offset + 2]) & 0xff) << 8 |
            (ord($hmac[$offset + 3]) & 0xff);
        return str_pad($code % 10**$this->digits, $this->digits, '0', STR_PAD_LEFT);
    }

    protected function verify($input, $generated) {
        if (!is_string($input))
            throw new \Exception('`otp` should be a String');

        return $this->time_constant_compare($input, $generated);
    }

    private function int_to_bytestring($int, $padding = 8) {
        if ($int < 0)
            throw new \Exception('#int_to_bytestring requires a positive number');

        $result = [];
        while ($int > 0) {
            array_push($result, chr($int & 0xFF));
            $int >>= 8;
        }
        return str_pad(implode(array_reverse($result)), $padding, chr(0), STR_PAD_LEFT);
    }

    private function byte_secret() {
        return Base32::decode($this->secret);
    }

    private function time_constant_compare($a, $b) {
        if (empty($a) || empty($b) || strlen($a) != strlen($b))
            return False;
        $l = unpack("c*", $a);
        $res = 0;
        foreach(unpack("c*", $b) as $byte) {
            $res |= $byte ^ array_shift($l);
        }
        return $res === 0;
    }
}
