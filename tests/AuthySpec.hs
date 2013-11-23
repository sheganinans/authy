{-# LANGUAGE OverloadedStrings #-}

module AuthySpec where

import Test.Hspec (Spec, context, describe, hspec, it, shouldReturn)

import Authy      (Format(..), newUser, sandboxServer, verify)

spec :: Spec
spec = do
    let key = "d57d919d11e6b221c9bf6f7c882028f9"

    describe "newUser" $ do
        {- curl http://sandbox-api.authy.com/protected/json/users/new?api_key=d57d919d11e6b221c9bf6f7c882028f9 \
           -d user[email]="user@domain.com" \
           -d user[cellphone]="317-338-9302" \
           -d user[country_code]="54" -}
        context "Valid new user request" $
            it "returns a user ID" $
                newUser sandboxServer JSON key "user@domain.com" "317-338-9302" 54 `shouldReturn` Right 209

        {- curl http://sandbox-api.authy.com/protected/json/users/new?api_key=d57d919d11e6b221c9bf6f7c882028f9 \
           -d user[email]="user.com" \
           -d user[cellphone]="AAA-338-9302" \
           -d user[country_code]="1" -}
        context "Request with an invalid e-mail" $
            it "returns an error message" $
                newUser sandboxServer JSON key "user.com" "AAA-338-9302" 1 `shouldReturn` Left ("User was not valid", ["email"])

        {- curl http://sandbox-api.authy.com/protected/json/users/new?api_key=d57d919d11e6b221c9bf6f7c882028f9 \
           -d user[email]="user.com" \
           -d user[cellphone]="AAA-338-9302" \
           -d user[country_code]="999" -}
        context "Request with errors an invalid e-mail and country code" $
            it "returns an error message" $
                newUser sandboxServer JSON key "user.com" "AAA-338-9302" 999 `shouldReturn` Left ("User was not valid", ["email", "country_code"])

        {- curl http://sandbox-api.authy.com/protected/json/users/new?api_key=d57d919d11e6b221c9bf6f7c882028f9 \
           -d user[email]="user.com" \
           -d user[cellphone]="AAA-338-9302" \
           -d user[country_code]="999" -}
        context "Request with an invalid e-mail and cell phone" $
            it "returns an error message" $
                newUser sandboxServer JSON key "user.com" "" 1 `shouldReturn` Left ("User was not valid", ["email", "cellphone"])

    describe "verify" $ do
        -- curl -i http://sandbox-api.authy.com/protected/json/verify/0000000/1?api_key=d57d919d11e6b221c9bf6f7c882028f9
        context "Verification of a valid token" $
            it "returns True" $
                verify sandboxServer JSON key "0000000" "1" False `shouldReturn` Right True

        -- curl -i http://sandbox-api.authy.com/protected/json/verify/1234567/1\?api_key\=d57d919d11e6b221c9bf6f7c882028f9
        context "Verification of a non-existent user" $
            it "returns an error message" $
                verify sandboxServer JSON key "1234567" "1" False `shouldReturn` Left "User doesn't exist."

        -- curl -i http://sandbox-api.authy.com/protected/json/verify/939393/3?api_key=d57d919d11e6b221c9bf6f7c882028f9
        context "When a user has not finished registration" $ 
            it "returns False" $
                verify sandboxServer JSON key "939393" "3" False `shouldReturn` Right False

        -- curl -i http://sandbox-api.authy.com/protected/json/verify/939393/3?api_key=d57d919d11e6b221c9bf6f7c882028f9\&force=true
        context "Forced verification on user who has not finished registration" $
            it "returns False" $
                verify sandboxServer JSON key "939393" "3" True `shouldReturn` Right False

main :: IO ()
main = hspec spec
