<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2019 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core;

use InvalidArgumentException;

class AlgorithmManagerFactory
{
    /**
     * @var array
     */
    private $algorithms = [];
    /**
     * Adds an algorithm.
     *
     * Each algorithm is identified by an alias hence it is allowed to have the same algorithm twice (or more).
     * This can be helpful when an algorithm have several configuration options.
     */
    public function add($alias, Algorithm $algorithm)
    {
        $this->algorithms[$alias] = $algorithm;
    }
    /**
     * Returns the list of aliases.
     *
     * @return string[]
     */
    public function aliases()
    {
        return array_keys($this->algorithms);
    }
    /**
     * Returns all algorithms supported by this factory.
     * This is an associative array. Keys are the aliases of the algorithms.
     *
     * @return Algorithm[]
     */
    public function all()
    {
        return $this->algorithms;
    }
    /**
     * Create an algorithm manager using the given aliases.
     *
     * @param string[] $aliases
     */
    public function create(array $aliases)
    {
        $algorithms = [];
        foreach ($aliases as $alias) {
            if (!\is_string($alias)) {
                throw new InvalidArgumentException('Invalid alias');
            }
            if (!isset($this->algorithms[$alias])) {
                throw new InvalidArgumentException(sprintf('The algorithm with the alias "%s" is not supported.', $alias));
            }
            $algorithms[] = $this->algorithms[$alias];
        }
        return new AlgorithmManager($algorithms);
    }
}
