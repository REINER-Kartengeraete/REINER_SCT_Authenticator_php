<?php

// MIT LICENSE
//
// $Date: Wed Jul 22 11:43:18 2020 +0200$
// $Rev: v1.0.0-18-ge8d4816$

namespace RSCT_OTP;

class TOTP extends OTP
{
    const DEFAULT_INTERVAL = 30;

    function __construct($s, $options = []) {
        $this->interval = isset($options["interval"]) ?
            $options["interval"] : self::DEFAULT_INTERVAL;
        $this->issuer = isset($options["issuer"]) ?
            $options["issuer"] : null;
        parent::__construct($s, $options);
    }

    public function at($time) {
        return $this->generate_otp($this->timecode($time));
    }

    public function verify($otp, $options = []) {
        $at = isset($options["at"]) ?
            $options["at"] : time();
        $drift_ahead = isset($options["drift_ahead"]) ?
            $options["drift_ahead"] : 0;
        $drift_behind = isset($options["drift_behind"]) ?
            $options["drift_behind"] : 0;
        $after = isset($options["after"]) ?
            $options["after"] : null;

        $timecodes = $this->get_timecodes($at, $drift_behind, $drift_ahead);
        if ($after)
            $timecodes = array_filter($timecodes, function($t) use ($after) {
                return $t > $this->timecode($after);
            });

        $result = null;
        foreach($timecodes as $t) {
            if (parent::verify($otp, $this->generate_otp($t))) {
                $result = $t * $this->interval;
            }
        }
        return $result;
    }

    // Returns the provisioning URI for the OTP
    // This can then be encoded in a QR Code and used
    // to provision the Google Authenticator app
    // param [String] name of the account
    // return [String] provisioning URI
    public function provisioning_uri($name) {
        // The format of this URI is documented at:
        // https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        // For compatibility the issuer appears both before that account name and also in the
        // query string.
        $issuer = rawurlencode($this->issuer);
        if ($issuer !== "")
            $issuer .= ":";
        $uri = "otpauth://totp/".$issuer.$this->customencode($name)."?secret={$this->secret}";
        if ($this->issuer)
            $uri .= "&issuer=" . rawurlencode($this->issuer);
        if ($this->digits != self::DEFAULT_DIGITS)
            $uri .= "&digits=" . $this->digits;
        if ($this->interval != self::DEFAULT_INTERVAL)
            $uri .= "&period=" . $this->interval;
        if ($this->digest != "sha1")
            $uri .= "&algorithm=" . strtoupper($this->digest);
        return $uri;
    }

    public function now() {
        return $this->at(time());
    }

    private function get_timecodes($at, $drift_behind, $drift_ahead) {
        $now = $at;
        $timecode_start = $this->timecode($now - $drift_behind);
        $timecode_end = $this->timecode($now + $drift_ahead);

        return range($timecode_start, $timecode_end, 1);
    }

    private function timecode($time) {
        return intdiv($time, $this->interval);
    }

    // does not encode @
    private function customencode($str) {
        return str_replace("%40", "@", rawurlencode($str));
    }
}
