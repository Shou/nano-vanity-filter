
{-# LANGUAGE TypeApplications,
             PartialTypeSignatures,
             OverloadedStrings,
             OverloadedLists,
             BangPatterns
#-}

module Lib where

import qualified Crypto.Hash.BLAKE2.BLAKE2b as Blake2
import Control.Monad
import qualified Control.Monad.STM as STM
import Control.Concurrent
import qualified Control.Concurrent.STM.TQueue as STM
import qualified Control.Concurrent.MVar as Mut
import qualified Control.Exception as Except
import qualified Control.Lens as Lens
import Control.Monad
import qualified Crypto.ECC.Edwards25519 as Ecced
import qualified Crypto.Error as Cerr
import qualified Crypto.PubKey.Ed25519 as Ced
import qualified Data.Base32String as Base32
import Data.Bits
import qualified Data.ByteArray as BArray
import qualified Data.ByteString as Bytes
import qualified Data.ByteString.Char8 as Bytes8
import Data.Coerce
import qualified Data.HexString as Hex
import Data.List
import qualified Data.Map.Strict as Map
import Data.Maybe
import Data.Monoid
import qualified Data.Set as Set
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TEnc
import qualified Data.Text.IO as Text
import qualified Data.Vector as Vector
import qualified Data.Word as Word
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
    = "Wallet \n\tSeed "
      <> showAsHEX seed <> "\n\tPrivate key "
      <> showAsHEX priv <> "\n\tPublic key "
      <> showAsHEX pub <> "\n\tAddress "
      <> Bytes8.unpack addr

data Match =
  Match { getMatchWords :: Set.Set Bytes.ByteString
        , getMatchSeed :: Bytes.ByteString
        , getMatchAddr :: Bytes.ByteString
        }

instance Show Match where
  show (Match ws sd ad) = "Match "
    <> (Bytes8.unpack $ Bytes.intercalate ", " $ Set.toList ws)
    <> "\n\t"
    <> showAsHEX sd
    <> "\n\t"
    <> Bytes8.unpack ad

showAsHEX = Text.unpack . Text.toUpper . Hex.toText . Hex.fromBytes
hexToBytes = Hex.toBytes . Hex.hexString . TEnc.encodeUtf8 . Text.toLower

shouldDebug = False

debugPrint :: Show a => a -> IO ()
debugPrint = when shouldDebug . print


americanEnglishFilename = "/home/benedict/.cccccc/american-english-long"

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


-- Utils

over :: Bytes.ByteString -> _ -> _ -> Bytes.ByteString
over byteString index func = Lens.over (Lens.ix index) func byteString

nonAlphabet c = c < 76 || c > 122

-- / Utils

makeNanoPriv :: _ -> _
makeNanoPriv = Blake2.hash 32 mempty

makeNanoPubkey :: Bytes.ByteString -> Bytes.ByteString
makeNanoPubkey privkey =
  let hashedPrivkey = Bytes.take 32 $ Blake2.hash 64 mempty privkey
      clampedHash0 = over hashedPrivkey 0 (.&. 248)
      clampedHash = over clampedHash0 31 (\n -> n .&. 127 .|. 64)
      scalar = Cerr.throwCryptoError . Ecced.scalarDecodeLong $ clampedHash
      point = Ecced.pointEncode $ Ecced.toPoint scalar
  in point

makeNanoAddress :: Bytes.ByteString -> Bytes.ByteString
makeNanoAddress bs = TEnc.encodeUtf8 $ prefix <> account <> checksum
  where
    prefix = "xrb_"
    paddedBs = if Bytes.head bs < 128 then 0 `Bytes.cons` bs else bs
    account = Base32.toText $ nanoBase32 paddedBs
    checksum = Base32.toText $ nanoBase32 $ Bytes.reverse $ Blake2.hash 5 mempty bs

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

generateNanoVanities :: STM.TQueue (_, Wallet)
                     -> Map.Map Word.Word8 (Set.Set Bytes.ByteString)
                     -> IO ()
generateNanoVanities queue englishDict = Except.catch
  (forever $ newNanoWallet >>= printScore queue englishDict)
  (const @_ @Except.SomeException $ generateNanoVanities queue englishDict)

vanityMatchQuantity :: _ -> Bytes.ByteString -> Set.Set Bytes.ByteString
vanityMatchQuantity englishDict addr = containsWord mempty addr
  where
    containsWord :: Set.Set Bytes.ByteString -> Bytes.ByteString -> Set.Set Bytes.ByteString
    containsWord wordAcc addrTail =
      let firstLetter = Bytes.head addrTail
          wordSet = fromMaybe mempty $ Map.lookup firstLetter englishDict
          matcher = flip Bytes.isPrefixOf addrTail
          match = find matcher wordSet
      in case () of
              -- We require words to be at least 4 chars long
           _ | Bytes.length addrTail < 4 -> wordAcc
              -- We don't want to try to match non-alphabetical characters
             | Just n <- Bytes.findIndex nonAlphabet (Bytes.take 4 addrTail) ->
                 containsWord wordAcc $ Bytes.drop (n + 1) addrTail
             | otherwise ->
                 maybe (containsWord wordAcc $ Bytes.tail addrTail)
                       (\word -> containsWord (Set.insert word wordAcc) $ Bytes.drop (Bytes.length word) addrTail)
                       match

printScore :: STM.TQueue (_, Wallet)
           -> Map.Map Word.Word8 (Set.Set Bytes.ByteString)
           -> Wallet
           -> IO ()
printScore queue englishDict wallet = do
  let matches = vanityMatchQuantity englishDict $ getAddress wallet
  when (length matches > 3) $ STM.atomically $ STM.writeTQueue queue (matches, wallet)

runPrinter queue = forever $ do
  (matches, wallet) <- STM.atomically $ STM.readTQueue queue
  print $ Match matches (getSeed wallet) (getAddress wallet)

incMVar :: Mut.MVar Int
incMVar = unsafePerformIO $ Mut.newMVar 0
incQuantity = Mut.modifyMVar_ incMVar (pure . (+1))

wordsToDict :: [Bytes.ByteString] -> Map.Map Word.Word8 (Set.Set Bytes.ByteString)
wordsToDict = foldl' go mempty
  where
    go accMap word =
      let firstLetter = Bytes.head word
          inserter wordListMay = Just . Set.insert word $ fromMaybe mempty wordListMay
      in Map.alter inserter firstLetter accMap

loadEnglishDict = wordsToDict . filterEmpties . bsWords <$> Bytes.readFile americanEnglishFilename
  where
    newLineChar = 10
    bsWords = Bytes.split newLineChar
    filterEmpties = filter (/= mempty)

-- | Average addresses per second estimate
printSpeed n = do
    threadDelay (10^7)
    putStr $ show n ++ "0 seconds: "
    readMVar incMVar >>= print
    printSpeed $ n + 1

someFunc :: IO ()
someFunc = do
    printerQueue <- STM.newTQueueIO
    englishDict <- loadEnglishDict

    --forkIO $ printSpeed 1

    forM_ @[] @IO @Int [1 .. 1] $ \workerNumber -> forkIO $ do
      generateNanoVanities printerQueue englishDict

    runPrinter printerQueue

