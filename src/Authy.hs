{-# LANGUAGE OverloadedStrings #-}

module Authy
    ( Format(JSON)
    , newUser
    , verify
    , apiServer
    , sandboxServer
    ) where

import           Data.Aeson            ((.:), Object, Value(..), withObject)
import           Data.Aeson.Types      (Parser)
import qualified Data.HashMap.Strict   as HM
import           Data.Text             (unpack)
import           Network.Curl.Aeson    (curlAeson, noData)
import           Network.Curl.Opts     (CurlOption(..))


-------------------------------------------------------------------------------

data Format = XML | JSON deriving Eq

instance Show Format where
    show JSON = "json"
    show XML  = "xml"


-------------------------------------------------------------------------------

apiServer, sandboxServer :: String
apiServer     = "https://api.authy.com"        -- Production API
sandboxServer = "http://sandbox-api.authy.com" -- Sandbox API (great for automated testing)


-------------------------------------------------------------------------------

newUserResponseParser :: Value -> Parser (Either (String, [String]) Int)
newUserResponseParser = withObject "new user response" $ \obj -> do
    success <- obj  .: "success"
    case success of
        "true"  -> do
            user    <- obj  .: "user"
            user_id <- user .: "id"
            return $ Right user_id
        "false" -> do
            message <- obj  .: "message"
            errors  <- obj  .: "errors"  :: Parser Object
            let invalid = [unpack key | (key, valid) <- zip keys (map (flip HM.member errors) keys), valid]
            return $ Left (message, invalid)
        _       -> return $ Left ("The 'impossible' happened: Unknown value for key 'success': '" ++ success ++ "'", [])
    where
        keys = ["email", "cellphone", "country_code"]

-- | Enabling two-factor authentication on a user
newUser
    :: String
    -- ^ "https://api.authy.com" or "http://sandbox-api.authy.com"
    -> Format
    -- ^ JSON or XML
    -> String
    -- ^ Your private API key
    -> String
    -- ^ E-mail
    -> String
    -- ^ Cell phone. Used by the API to match the user
    -> Int
    -- ^ Numeric calling country code of the country. Eg: 1 for the US. 91 for India. 54 for Mexico
    -> IO (Either (String, [String]) Int)
    -- ^ Either an error message or a user ID
newUser server format key email cellPhone countryCode
    | format == XML = error "XML requests are not yet implemented"
    | otherwise     = curlAeson newUserResponseParser "POST" (server ++ path)
                          [CurlFailOnError False, CurlPostFields formData] noData
    where
        formData = ["user[email]=" ++ email
                   ,"user[cellphone]=" ++ cellPhone
                   ,"user[country_code]=" ++ show countryCode]
        path     = "/protected/" ++ show format ++ "/users/new?api_key=" ++ key


-------------------------------------------------------------------------------

verifyResponseParser :: Value -> Parser (Either String Bool)
verifyResponseParser = withObject "VerifyResponse" $ \obj -> do
    success <- obj  .: "success"
    case success of
        "true"  -> return $ Right True
        "false" -> do
            message <- obj .: "message"
            case message of
                "token is invalid" -> return $ Right False
                _                  -> return $ Left message
        _       -> return $ Left $ "The 'impossible' happened: Unknown value for key 'success': '" ++ success ++ "'"

-- | Verifying a user token
verify
    :: String
    -- ^ "https://api.authy.com" or "http://sandbox-api.authy.com"
    -> Format
    -- ^ JSON or XML
    -> String
    -- ^ Your private API key
    -> String
    -- ^ The token you are verifying
    -> String
    -- ^ The authy ID that was sent back when registering the users device
    -> Bool
    -- ^ Force token verification on unregistered user
    -> IO (Either String Bool)
    -- ^ Either an error message or a Boolean indicating whether the token is valid
verify server format key token authyID force
    | format == XML = error "XML requests are not yet implemented"
    | otherwise     = curlAeson verifyResponseParser "GET" url [CurlFailOnError False] noData
    where
        url = server ++ "/protected/" ++ show format ++ "/verify/" ++ token ++ "/" ++ authyID ++ "?api_key=" ++ key ++ if force then "&force=true" else ""
