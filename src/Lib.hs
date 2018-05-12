
{-# LANGUAGE TypeApplications #-}

module Lib
    ( someFunc
    ) where

import qualified Crypto.Hash.BLAKE2.BLAKE2b as Blake2
import Control.Monad
import qualified Control.Monad.STM as STM
import Control.Concurrent
import qualified Control.Concurrent.STM.TQueue as STM
import qualified Control.Exception as Except
import Control.Monad
import qualified Crypto.Sign.Ed25519 as Ed
import Data.Bits (shiftR, (.&.))
import qualified Data.ByteString as Bytes
import qualified Data.ByteString.Char8 as Bytes8
import Data.Coerce
import qualified Data.HexString as Hex
import Data.Monoid
import qualified Data.Text as Text
import qualified Data.Text.IO as Text
import qualified Data.Vector as Vector
import qualified Data.Word as Word
import qualified System.Process as Proc
import qualified System.Random as Rand


data Wallet =
  Wallet { seed :: Bytes.ByteString
         , privateKey :: Bytes.ByteString
         , publicKey :: Bytes.ByteString
         }

instance Show Wallet where
  show (Wallet seed priv pub) = "Wallet \n\tSeed "
                             <> (Text.unpack . Hex.toText $ Hex.fromBytes seed) <> "\n\tPrivate key "
                             <> (Text.unpack . Hex.toText $ Hex.fromBytes priv) <> "\n\tPublic key "
                             <> (Text.unpack . Hex.toText $ Hex.fromBytes pub)

newtype Seed = Seed Bytes.ByteString


shouldDebug = False

debugPrint = when shouldDebug . print


generateNanoPriv = Blake2.hash 32 mempty

generateNanoWallet = do
  byteSeed <- Bytes.pack <$> replicateM 32 (Rand.randomIO @Word.Word8)
  let index = Bytes.pack [2, 0, 1, 8]
      privkey = generateNanoPriv $ byteSeed <> index
      pubkey = Ed.unPublicKey $ Ed.toPublicKey $ Ed.SecretKey privkey
  return $ Wallet (byteSeed <> index) privkey pubkey

byteStringToHEX bs = join $ map getPos $ Bytes.unpack bs
  where
    getPos byte = [ byte `shiftR` 4, byte .&. 0xF ]
    hexchars = "0123456789ABCDEF"

runNanoVanity queue = do
  (flip $ maybe (debugPrint "runNanoVanity: no output")) mayStdout $ \stdout -> do
    vanityLines <- Text.lines <$> Text.hGetContents stdout
    let maybePair = do
          (_ : seed : addr : rest) <- Just vanityLines
          let seed' = last $ Text.words seed
              addr' = last $ Text.words addr
          return (seed', addr')
    maybe (debugPrint "runNanoVanity: no pair output") (STM.atomically . STM.writeTQueue queue) maybePair

generateNanoVanities queue = Except.catch
  (forever $ runNanoVanity queue)
  (const @_ @Except.SomeException $ generateNanoVanities queue)

vanityMatchQuantity englishDict (seed, addr) =
  let containsWord acc word = if Text.isInfixOf word addr then acc + 1 else acc
  in foldl containsWord 0 englishDict

someFunc :: IO ()
someFunc = do
  queue <- STM.newTQueueIO
  englishDict <- (Vector.fromList . Text.lines) <$> Text.readFile "/home/benedict/.cccccc/american-english-long"
  generateNanoWallet >>= print
  when False $ do
    pair <- STM.atomically (STM.readTQueue queue)
    let score = vanityMatchQuantity englishDict pair
    when (score > 3) $ do
      print score
      Text.putStrLn $ fst pair
      Text.putStrLn $ snd pair

