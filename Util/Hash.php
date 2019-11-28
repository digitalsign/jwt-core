<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core\Util;

/**
 * @internal
 */
class Hash
{
    /**
     * Hash Parameter.
     *
     * @var string
     */
    private $hash;
    /**
     * DER encoding T.
     *
     * @var string
     */
    private $t;
    /**
     * Hash Length.
     *
     * @var int
     */
    private $length;
    private function __construct($hash, $length, $t)
    {
        $this->hash = $hash;
        $this->length = $length;
        $this->t = $t;
    }
    /**
     * @return Hash
     */
    public static function sha1()
    {
        return new self('sha1', 20, "0!0\t\6\5+\16\3\2\32\5\0\4\24");
    }
    /**
     * @return Hash
     */
    public static function sha256()
    {
        return new self('sha256', 32, "010\r\6\t`�H\1e\3\4\2\1\5\0\4 ");
    }
    /**
     * @return Hash
     */
    public static function sha384()
    {
        return new self('sha384', 48, "0A0\r\6\t`�H\1e\3\4\2\2\5\0\0040");
    }
    /**
     * @return Hash
     */
    public static function sha512()
    {
        return new self('sha512', 64, "0Q0\r\6\t`�H\1e\3\4\2\3\5\0\4@");
    }
    public function getLength()
    {
        return $this->length;
    }
    /**
     * Compute the HMAC.
     */
    public function hash($text)
    {
        return hash($this->hash, $text, true);
    }
    public function name()
    {
        return $this->hash;
    }
    public function t()
    {
        return $this->t;
    }
}
