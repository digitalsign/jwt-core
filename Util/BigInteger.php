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

use GMP;

/**
 * @internal
 */
class BigInteger
{
    /**
     * Holds the BigInteger's value.
     *
     * @var GMP
     */
    private $value;
    private function __construct(GMP $value)
    {
        $this->value = $value;
    }
    /**
     * @return BigInteger
     */
    public static function createFromGMPResource(GMP $value)
    {
        return new self($value);
    }
    /**
     * @return BigInteger
     */
    public static function createFromBinaryString($value)
    {
        $value = '0x' . unpack('H*', $value)[1];
        $value = gmp_init($value, 16);
        return new self($value);
    }
    /**
     * @return BigInteger
     */
    public static function createFromDecimal($value)
    {
        $value = gmp_init($value, 10);
        return new self($value);
    }
    /**
     * Converts a BigInteger to a binary string.
     */
    public function toBytes()
    {
        if (0 === gmp_cmp($this->value, gmp_init(0))) {
            return '';
        }
        $temp = gmp_strval(gmp_abs($this->value), 16);
        $temp = 0 !== (mb_strlen($temp, '8bit') & 1) ? '0' . $temp : $temp;
        $temp = hex2bin($temp);
        return ltrim($temp, \chr(0));
    }
    /**
     * Adds two BigIntegers.
     *
     *  @param BigInteger $y
     *
     *  @return BigInteger
     */
    public function add(self $y)
    {
        $value = gmp_add($this->value, $y->value);
        return self::createFromGMPResource($value);
    }
    /**
     * Subtracts two BigIntegers.
     *
     *  @param BigInteger $y
     *
     *  @return BigInteger
     */
    public function subtract(self $y)
    {
        $value = gmp_sub($this->value, $y->value);
        return self::createFromGMPResource($value);
    }
    /**
     * Multiplies two BigIntegers.
     *
     * @param BigInteger $x
     *
     *  @return BigInteger
     */
    public function multiply(self $x)
    {
        $value = gmp_mul($this->value, $x->value);
        return self::createFromGMPResource($value);
    }
    /**
     * Divides two BigIntegers.
     *
     * @param BigInteger $x
     *
     *  @return BigInteger
     */
    public function divide(self $x)
    {
        $value = gmp_div($this->value, $x->value);
        return self::createFromGMPResource($value);
    }
    /**
     * Performs modular exponentiation.
     *
     * @param BigInteger $e
     * @param BigInteger $n
     *
     * @return BigInteger
     */
    public function modPow(self $e, self $n)
    {
        $value = gmp_powm($this->value, $e->value, $n->value);
        return self::createFromGMPResource($value);
    }
    /**
     * Performs modular exponentiation.
     *
     * @param BigInteger $d
     *
     * @return BigInteger
     */
    public function mod(self $d)
    {
        $value = gmp_mod($this->value, $d->value);
        return self::createFromGMPResource($value);
    }
    /**
     * Calculates modular inverses.
     *
     * @param BigInteger $n
     *
     * @return BigInteger
     */
    public function modInverse(self $n)
    {
        $value = gmp_invert($this->value, $n->value);
        return self::createFromGMPResource($value);
    }
    /**
     * Compares two numbers.
     *
     * @param BigInteger $y
     */
    public function compare(self $y)
    {
        return gmp_cmp($this->value, $y->value);
    }
    /**
     * @param BigInteger $y
     */
    public function equals(self $y)
    {
        return 0 === $this->compare($y);
    }
    /**
     * @param BigInteger $y
     *
     * @return BigInteger
     */
    public static function random(self $y)
    {
        $zero = self::createFromDecimal(0);
        return self::createFromGMPResource(gmp_random_range($zero->value, $y->value));
    }
    /**
     * @param BigInteger $y
     *
     * @return BigInteger
     */
    public function gcd(self $y)
    {
        return self::createFromGMPResource(gmp_gcd($this->value, $y->value));
    }
    /**
     * @param BigInteger $y
     */
    public function lowerThan(self $y)
    {
        return 0 > $this->compare($y);
    }
    public function isEven()
    {
        $zero = self::createFromDecimal(0);
        $two = self::createFromDecimal(2);
        return $this->mod($two)->equals($zero);
    }
}
