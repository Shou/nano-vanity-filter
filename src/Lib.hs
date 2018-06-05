
{-# LANGUAGE TypeApplications,
             PartialTypeSignatures,
             OverloadedStrings,
             OverloadedLists
#-}

module Lib where

import qualified Crypto.Hash.BLAKE2.BLAKE2b as Blake2
import Control.Monad
import qualified Control.Monad.STM as STM
import Control.Concurrent
import qualified Control.Concurrent.STM.TQueue as STM
import qualified Control.Exception as Except
import qualified Control.Lens as Lens
import Control.Monad
import qualified Crypto.ECC.Edwards25519 as Ecced
import qualified Crypto.Error as Cerr
import qualified Crypto.PubKey.Ed25519 as Ced
import qualified Crypto.Sign.Ed25519 as Sed
import qualified Data.Base32String as Base32
import Data.Bits
import qualified Data.ByteArray as BArray
import qualified Data.ByteString as Bytes
import qualified Data.ByteString.Char8 as Bytes8
import Data.Coerce
import qualified Data.HexString as Hex
import Data.Maybe
import Data.Monoid
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TEnc
import qualified Data.Text.IO as Text
import qualified Data.Vector as Vector
import qualified Data.Word as Word
import qualified System.Process as Proc
import qualified System.Random as Rand


data Wallet =
  Wallet { seed :: Bytes.ByteString
         , privateKey :: Bytes.ByteString
         , publicKey :: Bytes.ByteString
         , address :: Text.Text
         }

instance Show Wallet where
  show (Wallet seed priv pub addr)
    = "Wallet \n\tSeed "
      <> (Text.unpack . Text.toUpper . Hex.toText $ Hex.fromBytes seed) <> "\n\tPrivate key "
      <> (Text.unpack . Text.toUpper . Hex.toText $ Hex.fromBytes priv) <> "\n\tPublic key "
      <> (Text.unpack . Text.toUpper . Hex.toText $ Hex.fromBytes pub) <> "\n\tAddress "
      <> (Text.unpack addr)

newtype Seed = Seed Bytes.ByteString


shouldDebug = False

debugPrint :: Show a => a -> IO ()
debugPrint = when shouldDebug . print


nanoAlphabet = "13456789abcdefghijkmnopqrstuwxyz"
nanoBase32 = Base32.fromBytes nanoAlphabet


-- Utils

over byteString index func = Lens.over (Lens.ix index) func byteString

-- / Utils

makeNanoPriv = Blake2.hash 32 mempty

makeNanoPubkey privkey =
  let hashedPrivkey = Bytes.take 32 $ Blake2.hash 64 mempty privkey
      clampedHash0 = over hashedPrivkey 0 (.&. 248)
      clampedHash = over clampedHash0 31 (\n -> n .&. 127 .|. 64)
      scalar = Cerr.throwCryptoError . Ecced.scalarDecodeLong $ clampedHash
      point = Ecced.pointEncode $ Ecced.toPoint scalar
  in point

makeNanoAddress bs = prefix <> account <> checksum
  where
    prefix = "xrb_"
    account = Base32.toText $ nanoBase32 $ 0 `Bytes.cons` bs
    checksum = Base32.toText $ nanoBase32 $ Bytes.reverse $ Blake2.hash 5 mempty bs

makeNanoWalletFromTextSeed textSeed =
  let byteSeed = Hex.toBytes $ Hex.hexString $ TEnc.encodeUtf8 $ Text.toLower textSeed
  in makeNanoWalletFromSeed byteSeed

makeNanoWalletFromSeed byteSeed =
  let index = Bytes.pack [ 0, 0, 0, 0 ]
      privkey = makeNanoPriv $ byteSeed <> index
      pubkey = makeNanoPubkey privkey
      address = makeNanoAddress pubkey
  in Wallet byteSeed privkey pubkey address

newNanoWallet = do
  byteSeed <- Bytes.pack <$> replicateM 32 (Rand.randomIO @Word.Word8)
  return $ makeNanoWalletFromSeed byteSeed

generateNanoVanities queue = Except.catch
  (forever $ newNanoWallet >>= STM.atomically . STM.writeTQueue queue)
  (const @_ @Except.SomeException $ generateNanoVanities queue)

vanityMatchQuantity englishDict addr =
  let containsWord acc word = if Text.isInfixOf word addr then acc + 1 else acc
  in foldl containsWord 0 englishDict

someFunc :: IO ()
someFunc = do
  queue <- STM.newTQueueIO
  forkIO $ generateNanoVanities queue
  englishDict <- (Vector.fromList . Text.lines) <$> Text.readFile "/home/benedict/.cccccc/american-english-long"
  forever $ do
    wallet <- STM.atomically (STM.readTQueue queue)
    let score = vanityMatchQuantity englishDict $ address wallet
    when (score > 1) $ do
      print score
      print wallet

