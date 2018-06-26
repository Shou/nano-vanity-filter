
{-# LANGUAGE TypeApplications,
             PartialTypeSignatures,
             OverloadedStrings,
             OverloadedLists,
             BangPatterns,
             DataKinds,
             ScopedTypeVariables,
             RankNTypes,
             AllowAmbiguousTypes,
             KindSignatures,
             TypeOperators,
             TypeFamilies
#-}

module Lib where

import Control.Monad
import qualified Control.Monad.STM as STM
import Control.Concurrent
import qualified Control.Concurrent.STM.TQueue as STM
import qualified Control.Concurrent.MVar as Mut
import qualified Control.Exception as Except
import qualified Control.Lens as Lens
import Control.Monad
import Control.Type.Operator
import qualified Crypto.Hash as Hash
import qualified Crypto.ECC.Edwards25519 as Ecced
import qualified Crypto.Error as Cerr
import qualified Crypto.PubKey.Ed25519 as Ced
import qualified Data.Base32String as Base32
import Data.Bits
import qualified Data.ByteArray as BArray
import qualified Data.ByteString as Bytes
import qualified Data.ByteString.Char8 as Bytes8
import Data.Coerce
import qualified Data.HashTable.IO as HashT
import qualified Data.HexString as Hex
import Data.Int
import Data.List
import qualified Data.Map.Strict as Map
import Data.Maybe
import Data.Monoid
import Data.Proxy
import qualified Data.Set as Set
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TEnc
import qualified Data.Text.IO as Text
import qualified Data.Vector as Vector
import qualified Data.Word as Word
import GHC.Conc
import GHC.TypeLits
import System.IO.Unsafe
import qualified System.Process as Proc
import qualified System.Random as Rand


data Wallet =
  Wallet { getSeed :: Bytes.ByteString
         , getPrivateKey :: Bytes.ByteString
         , getPublicKey :: Bytes.ByteString
         , getAddress :: Bytes.ByteString
         }

instance Show Wallet where
  show (Wallet seed priv pub addr)
    = "Wallet \n\tSeed " <> showAsHEX seed -- <> "\n\t" <> show (Bytes.unpack seed)
      <> "\n\tPrivate key " <> showAsHEX priv -- <> "\n\t" <> show (Bytes.unpack priv)
      <> "\n\tPublic key " <> showAsHEX pub -- <> "\n\t" <> show (Bytes.unpack pub)
      <> "\n\tAddress " <> Bytes8.unpack addr -- <> "\n\t" <> show (Bytes.unpack addr)

data Match =
  Match { getMatchWords :: Vector.Vector Bytes.ByteString
        , getMatchSeed :: Bytes.ByteString
        , getMatchAddr :: Bytes.ByteString
        }

instance Show Match where
  show (Match ws sd ad) = "Match "
    <> (Bytes8.unpack $ Bytes.intercalate ", " $ Vector.toList ws)
    <> "\n\t"
    <> showAsHEX sd
    <> "\n\t"
    <> Bytes8.unpack ad

type HashSet k = HashT.BasicHashTable k ()


setLookup :: (Eq k, _) => HashT.BasicHashTable k () -> k -> IO $ Maybe k
setLookup set word = maybe Nothing (Just . const word) <$> HashT.lookup set word

showAsHEX = Text.unpack . Text.toUpper . Hex.toText . Hex.fromBytes
hexToBytes = Hex.toBytes . Hex.hexString . TEnc.encodeUtf8 . Text.toLower

shouldDebug = False

debugPrint :: Show a => a -> IO ()
debugPrint = when shouldDebug . print


americanEnglishFilename = "/home/benedict/.cccccc/american-english-long"

prefix = "xrb_"

nanoAlphabet = "13456789abcdefghijkmnopqrstuwxyz"
nanoBase32 = Base32.fromBytes nanoAlphabet
nanoBase32' = Bytes.foldl' go (0, 0)
  where
    go (carry, acc) byte = undefined
      {- let bit16 :: Word.Word16
          bit16 = (fromIntegral byte .|. shiftL carry 8)
          bit5 :: Word.Word8
          bit5 = fromIntegral $ bit16 `shiftR` 3
          newCarry = bit5 .&. 7
          word8 = Bytes.singleton $ nanoAlphabet `Bytes.index` bit5
      in (newCarry, acc <> word8) -}

englishDict :: HashSet Bytes.ByteString
englishDict = unsafePerformIO HashT.new


-- Utils

over :: Bytes.ByteString -> Int -> (Word.Word8 -> Word.Word8) -> Bytes.ByteString
over byteString index func = Lens.over (Lens.ix index) func byteString

nonAlphabet c = c < 76 || c > 122

-- / Utils

-- | Hasher function that takes a bit length as a proxy argument, e.g.
--
-- > hash (Proxy :: Proxy (Blake2b 256))
--
-- or with TypeApplications
--
-- > hash (Proxy @(Blake2b 256))
hash :: forall hasher. Hash.HashAlgorithm hasher => Proxy hasher -> Bytes.ByteString -> Bytes.ByteString
hash _ = BArray.convert . Hash.hash @_ @hasher

makeNanoPriv :: Bytes.ByteString -> Bytes.ByteString
makeNanoPriv = hash $ Proxy @(Hash.Blake2b 256)

makeNanoPubkey :: Bytes.ByteString -> Bytes.ByteString
makeNanoPubkey privkey =
  let hashedPrivkey = Bytes.take 32 $ hash (Proxy @(Hash.Blake2b 512)) privkey
      clampedHash0 = over hashedPrivkey 0 (.&. 248)
      clampedHash = over clampedHash0 31 (\n -> n .&. 127 .|. 64)
      scalar = Cerr.throwCryptoError . Ecced.scalarDecodeLong $ clampedHash
      point = Ecced.pointEncode $ Ecced.toPoint scalar
  in point

makeNanoAddress :: Bytes.ByteString -> Bytes.ByteString
makeNanoAddress bs = TEnc.encodeUtf8 $ prefix <> account <> checksum
  where
    paddedBs = if Bytes.head bs < 128 then 0 `Bytes.cons` bs else bs
    account = Base32.toText $ nanoBase32 paddedBs
    checksum = Base32.toText $ nanoBase32 $ Bytes.reverse $ hash (Proxy @(Hash.Blake2b 40)) bs

makeNanoWalletFromTextSeed :: Text.Text -> Wallet
makeNanoWalletFromTextSeed textSeed =
  let byteSeed = hexToBytes textSeed
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

generateNanoVanities :: STM.TQueue (Vector.Vector Bytes.ByteString, Wallet)
                     -> Int
                     -> IO ()
generateNanoVanities queue score = Except.catch
  (forever $ newNanoWallet >>= printScore queue score)
  (const @_ @Except.SomeException $ generateNanoVanities queue score)

vanityMatchQuantity :: Bytes.ByteString -> IO $ Vector.Vector Bytes.ByteString
vanityMatchQuantity addr = containsWord mempty $ Bytes.drop (Text.length prefix + 1) addr
  where
    containsWord :: Vector.Vector Bytes.ByteString -> Bytes.ByteString -> IO $ Vector.Vector Bytes.ByteString
    containsWord wordAcc addrTail = case () of
        -- We require words to be at least 4 chars long
      _ | Bytes.length addrTail < 4 -> return wordAcc

        -- We don't want to try to match non-alphabetical characters
        | Just n <- Bytes.findIndex nonAlphabet (Bytes.take 4 addrTail) ->
           containsWord wordAcc $ Bytes.drop (n + 1) addrTail

        | otherwise -> do
            -- Get the longest matching word
            let possibleWords = [ Bytes.take n addrTail | n <- [9, 8 .. 4] ]
            maybeMatch <- listToMaybe . catMaybes <$> mapM (setLookup englishDict) possibleWords
            maybe (containsWord wordAcc $ Bytes.tail addrTail)
                  (\word -> containsWord (Vector.snoc wordAcc word) $ Bytes.drop (Bytes.length word) addrTail)
                  maybeMatch

printScore :: STM.TQueue (Vector.Vector Bytes.ByteString, Wallet)
           -> Int
           -> Wallet
           -> IO ()
printScore queue score wallet = do
  incQuantity
  matches <- vanityMatchQuantity $ getAddress wallet
  when (length matches > score) $ STM.atomically $ STM.writeTQueue queue (matches, wallet)

runPrinter queue = forever $ do
  (matches, wallet) <- STM.atomically $ STM.readTQueue queue
  print $ Match matches (getSeed wallet) (getAddress wallet)

incMVar :: Mut.MVar Integer
incMVar = unsafePerformIO $ Mut.newMVar 0
incQuantity = Mut.modifyMVar_ incMVar increment
  where
    -- XXX(Shou): strict increment to remove space leaks when score isn't shown
    increment !n = return $! n + 1

wordsToDict :: [Bytes.ByteString] -> IO ()
wordsToDict = mapM_ $ \word -> HashT.insert englishDict word ()

-- TODO(Shou): return length of longest word so we know the upper boundary when searching, instead of 9
loadEnglishDict :: FilePath -> IO ()
loadEnglishDict = wordsToDict <=< (filter predicates . splitNewlines <$>) . Bytes.readFile
  where
    splitNewlines :: Bytes.ByteString -> [Bytes.ByteString]
    splitNewlines = Bytes.split 10
    predicates :: Bytes.ByteString -> Bool
    predicates word = not (Bytes.null word) && not (Bytes.any isNonWordLetter word)
    isNonWordLetter letter = nonAlphabet letter || letter == 108

-- | Average addresses per second estimate
printSpeed n = do
    threadDelay (10^7)
    putStr $ show n ++ "0 seconds: "
    readMVar incMVar >>= print
    printSpeed $ n + 1

someFunc :: () -> IO ()
someFunc options = do
    printerQueue <- STM.newTQueueIO
    loadEnglishDict americanEnglishFilename

    forkIO $ printSpeed 1

    let minScore = 3

    threadCount <- getNumProcessors
    forM_ @[] @IO @Int [1 .. threadCount] $ \workerNumber -> forkIO $ do
      generateNanoVanities printerQueue minScore

    runPrinter printerQueue

