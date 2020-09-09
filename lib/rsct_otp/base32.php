<?php

// MIT LICENSE
//
// $Date: Wed Jul 22 11:43:18 2020 +0200$
// $Rev: v1.0.0-18-ge8d4816$

namespace RSCT_OTP;

class Base32ErrorException extends \Exception { }

class Base32
{
    private static $chars = array(
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
        'Y', 'Z', '2', '3', '4', '5', '6', '7'  // 31
    );
    private static $shift = 5;
    private static $mask = 31;

    public static function decode($str) {
        $buffer = 0;
        $idx = 0;
        $bits_left = 0;
        $str = strtoupper(str_replace('=', '', $str));
        $result = array();
        foreach(str_split($str) as $char) {
            $buffer = $buffer << self::$shift;
            $buffer = $buffer | (self::decode_quint($char) & self::$mask);
            $bits_left = $bits_left + self::$shift;

            if ($bits_left >= 8) {
                $result[$idx] = ($buffer >> ($bits_left - 8)) & 255;
                $idx = $idx + 1;
                $bits_left = $bits_left - 8;
            }
        }
        return pack('c*', ...$result);
    }

    public static function encode($b) {
        $data = unpack('c*', $b);
        $out = "";
        $buffer = $data[1];
        $idx = 2;
        $bits_left = 8;
        while ($bits_left > 0 || $idx <= count($data)) {
            if ($bits_left < self::$shift) {
                if ($idx <= count($data)) {
                    $buffer = $buffer << 8;
                    $buffer = $buffer | ($data[$idx] & 255);
                    $bits_left = $bits_left + 8;
                    $idx = $idx + 1;
                } else {
                    $pad = self::$shift - $bits_left;
                    $buffer = $buffer << $pad;
                    $bits_left = $bits_left + $pad;
                }
            }
            $val = self::$mask & ($buffer >> ($bits_left - self::$shift));
            $bits_left = $bits_left - self::$shift;
            $out = $out . self::$chars[$val];
        }
        return $out;
    }

    // Defaults to 160 bit long secret (meaning a 32 character long base32 secret
    public static function random($byte_length = 20) {
        $rand_bytes = random_bytes($byte_length);
        return self::encode($rand_bytes);
    }

    private static function decode_quint($q) {
        $index = array_search($q, self::$chars);
        if ($index === FALSE)
            throw new Base32ErrorException("Invalid Base32 Character - '".$q."'");
        return $index;
    }
}
