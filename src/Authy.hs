{-# LANGUAGE OverloadedStrings #-}

-- | Tiny API client for <https://www.authy.com Authy> two-factor authentication
module Authy
    ( newUser
    , verify
    , productionServer
    , sandboxServer
    ) where

import           Data.Aeson            ((.:), Object, Value(..), withObject)
import           Data.Aeson.Types      (Parser)
import qualified Data.HashMap.Strict   as HM
import           Data.Text             (unpack)
import           Network.Curl.Aeson    (curlAeson, noData)
import           Network.Curl.Opts     (CurlOption(..))


-------------------------------------------------------------------------------

productionServer, sandboxServer :: String
-- | Production API server (<https://api.authy.com>).
productionServer = "https://api.authy.com"
-- | Sandbox API server (<http://sandbox-api.authy.com>). Great for automated testing.
sandboxServer    = "http://sandbox-api.authy.com"


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

-- | Enable two-factor authentication on a user.
newUser
    :: String
    -- ^ API server URL
    -> String
    -- ^ API key
    -> String
    -- ^ E-mail address
    -> String
    -- ^ Cell phone. Used by the API to match the user
    -> Int
    -- ^ Numeric calling country code of the country. E.g. 1 for the US, 91 for India, or 54 for Mexico
    -> IO (Either (String, [String]) Int)
    -- ^ Either an (error message, list of invalid parameters) pair or a user ID
newUser server key email cellPhone countryCode =
    curlAeson newUserResponseParser "POST" (server ++ path)
        [CurlFailOnError False, CurlPostFields formData] noData
    where
        formData = ["user[email]=" ++ email
                   ,"user[cellphone]=" ++ cellPhone
                   ,"user[country_code]=" ++ show countryCode]
        path     = "/protected/json/users/new?api_key=" ++ key


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

-- | Verify a user token.
verify
    :: String
    -- ^ API server URL
    -> String
    -- ^ API key
    -> String
    -- ^ The token you are verifying
    -> String
    -- ^ The Authy ID that was sent back when registering the users device
    -> Bool
    -- ^ Force token verification on unregistered user
    -> IO (Either String Bool)
    -- ^ Either an error message or a Boolean indicating whether the token is valid
verify server key token authyID force =
    curlAeson verifyResponseParser "GET" url [CurlFailOnError False] noData
    where
        url = server ++ "/protected/json/verify/" ++ token ++ "/" ++ authyID ++ "?api_key=" ++ key ++ if force then "&force=true" else ""
