<?php

/*
 * This file is part of the PHPASN1 library.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace FG\Utility;

/**
 * Class BigInteger
 * Utility class to remove dependence on a single large number library. Not intended for external use, this class only
 * implements the functionality needed throughout this project.
 *
 * Instances are immutable, all operations return a new instance with the result.
 *
 * @package FG\Utility
 * @internal
 */
abstract class BigInteger
{
    /**
     * Force a preference on the underlying big number implementation, useful for testing.
     * @var string|null
     */
    private static $_prefer;
    public static function setPrefer($prefer = null)
    {
        self::$_prefer = $prefer;
    }
    /**
     * Create a BigInteger instance based off the base 10 string or an integer.
     * @param string|int $val
     * @return BigInteger
     * @throws \InvalidArgumentException
     */
    public static function create($val)
    {
        if (self::$_prefer) {
            switch (self::$_prefer) {
                case 'gmp':
                    $ret = new BigIntegerGmp();
                    break;
                case 'bcmath':
                    $ret = new BigIntegerBcmath();
                    break;
                default:
                    throw new \UnexpectedValueException('Unknown number implementation: ' . self::$_prefer);
            }
        } else {
            // autodetect
            if (extension_loaded('gmp')) {
                $ret = new BigIntegerGmp();
            } elseif (extension_loaded('bcmath')) {
                $ret = new BigIntegerBcmath();
            } else {
                // TODO: potentially offer pure php implementation?
                throw new \RuntimeException('Requires GMP or bcmath extension.');
            }
        }
        if (is_int($val)) {
            $ret->_fromInteger($val);
        } else {
            // convert to string, if not already one
            $val = (string) $val;
            // validate string
            if (!preg_match('/^-?[0-9]+$/', $val)) {
                throw new \InvalidArgumentException('Expects a string representation of an integer.');
            }
            $ret->_fromString($val);
        }
        return $ret;
    }
    /**
     * BigInteger constructor.
     * Prevent directly instantiating object, use BigInteger::create instead.
     */
    protected function __construct()
    {
    }
    /**
     * Subclasses must provide clone functionality.
     * @return BigInteger
     */
    public abstract function __clone();
    /**
     * Assign the instance value from base 10 string.
     * @param string $str
     */
    protected abstract function _fromString($str);
    /**
     * Assign the instance value from an integer type.
     * @param int $integer
     */
    protected abstract function _fromInteger($integer);
    /**
     * Must provide string implementation that returns base 10 number.
     * @return string
     */
    public abstract function __toString();
    /* INFORMATIONAL FUNCTIONS */
    /**
     * Return integer, if possible. Throws an exception if the number can not be represented as a native integer.
     * @return int
     * @throws \OverflowException
     */
    public abstract function toInteger();
    /**
     * Is represented integer negative?
     * @return bool
     */
    public abstract function isNegative();
    /**
     * Compare the integer with $number, returns a negative integer if $this is less than number, returns 0 if $this is
     * equal to number and returns a positive integer if $this is greater than number.
     * @param BigInteger|string|int $number
     * @return int
     */
    public abstract function compare($number);
    /* MODIFY */
    /**
     * Add another integer $b and returns the result.
     * @param BigInteger|string|int $b
     * @return BigInteger
     */
    public abstract function add($b);
    /**
     * Subtract $b from $this and returns the result.
     * @param BigInteger|string|int $b
     * @return BigInteger
     */
    public abstract function subtract($b);
    /**
     * Multiply value.
     * @param BigInteger|string|int $b
     * @return BigInteger
     */
    public abstract function multiply($b);
    /**
     * The value $this modulus $b.
     * @param BigInteger|string|int $b
     * @return BigInteger
     */
    public abstract function modulus($b);
    /**
     * Raise $this to the power of $b and returns the result.
     * @param BigInteger|string|int $b
     * @return BigInteger
     */
    public abstract function toPower($b);
    /**
     * Shift the value to the right by a set number of bits and returns the result.
     * @param int $bits
     * @return BigInteger
     */
    public abstract function shiftRight($bits = 8);
    /**
     * Shift the value to the left by a set number of bits and returns the result.
     * @param int $bits
     * @return BigInteger
     */
    public abstract function shiftLeft($bits = 8);
    /**
     * Returns the absolute value.
     * @return BigInteger
     */
    public abstract function absoluteValue();
}