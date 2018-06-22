module Main where

import Lib

-- TODO
-- - pass optional dict file
--   - strip irrelevant words
--     - names, apostrophes, non-ASCII
-- - replace base32 function with more efficient version(?)
-- - consider a different matching approach
--   - take n of address tail where n is a word length n >= 4 up to the largest word for that first letter
--     - we can take care of length measuring in the dictionary
--     - O(log(n) * 3 * 55)
-- - use a hashmap with a constant lookup function

main :: IO ()
main = someFunc ()
