{-# LANGUAGE OverloadedStrings #-}

module AuthySpec where

import Test.Hspec (Spec, context, describe, hspec, it, shouldReturn)

import Authy      (newUser, sandboxServer, verify)

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
                newUser sandboxServer key "user@domain.com" "317-338-9302" 54 `shouldReturn` Right 209

        {- curl http://sandbox-api.authy.com/protected/json/users/new?api_key=d57d919d11e6b221c9bf6f7c882028f9 \
           -d user[email]="user.com" \
           -d user[cellphone]="AAA-338-9302" \
           -d user[country_code]="1" -}
        context "Request with an invalid e-mail" $
            it "returns an error message" $
                newUser sandboxServer key "user.com" "AAA-338-9302" 1 `shouldReturn` Left ("User was not valid.", ["email"])

        {- curl http://sandbox-api.authy.com/protected/json/users/new?api_key=d57d919d11e6b221c9bf6f7c882028f9 \
           -d user[email]="user.com" \
           -d user[cellphone]="AAA-338-9302" \
           -d user[country_code]="999" -}
        context "Request with errors an invalid e-mail and country code" $
            it "returns an error message" $
                newUser sandboxServer key "user.com" "AAA-338-9302" 999 `shouldReturn` Left ("User was not valid.", ["email", "country_code"])

        {- curl http://sandbox-api.authy.com/protected/json/users/new?api_key=d57d919d11e6b221c9bf6f7c882028f9 \
           -d user[email]="user.com" \
           -d user[cellphone]="AAA-338-9302" \
           -d user[country_code]="999" -}
        context "Request with an invalid e-mail and cell phone" $
            it "returns an error message" $
                newUser sandboxServer key "user.com" "" 1 `shouldReturn` Left ("User was not valid.", ["email", "cellphone"])

    describe "verify" $ do
        -- curl -i http://sandbox-api.authy.com/protected/json/verify/0000000/1?api_key=d57d919d11e6b221c9bf6f7c882028f9
        context "verification of a valid token" $
            it "returns True" $
                verify sandboxServer key "0000000" "1" False `shouldReturn` Right True

        -- curl -i http://sandbox-api.authy.com/protected/json/verify/1234567/1\?api_key\=d57d919d11e6b221c9bf6f7c882028f9
        context "verification of a non-existent user" $
            it "returns an error message" $
                verify sandboxServer key "1234567" "1" False `shouldReturn` Left "User doesn't exist."

        -- curl -i http://sandbox-api.authy.com/protected/json/verify/939393/3?api_key=d57d919d11e6b221c9bf6f7c882028f9
        context "when a user has not finished registration" $ 
            it "returns an error message" $
                verify sandboxServer key "939393" "3" False `shouldReturn` Left "User doesn't exist."

        -- curl -i http://sandbox-api.authy.com/protected/json/verify/939393/3?api_key=d57d919d11e6b221c9bf6f7c882028f9\&force=true
        context "forced verification on user who has not finished registration" $
            it "returns an error message" $
                verify sandboxServer key "939393" "3" True `shouldReturn` Left "User doesn't exist."

        -- curl -i http://sandbox-api.authy.com/protected/json/verify/939393/3?api_key=d57d919d11e6b221c9bf6f7c882028f8
        context "invalid API key" $
            it "returns an error message" $
                verify sandboxServer "0123456789abcdef0123456789abcdef" "939393" "3" True `shouldReturn` Left "Invalid API key."

main :: IO ()
main = hspec spec
