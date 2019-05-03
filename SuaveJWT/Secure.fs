module Secure

open JwtToken

open Microsoft.IdentityModel.Tokens
open Suave
open System.Security.Claims
open Suave.RequestErrors

type JwtConfig = {
    Issuer: string
    SecurityKey: SecurityKey
    ClientId: string
}

type AuthorizationResult =
    | Authorized
    | UnAuthorized of string

let jwtAuthenticate jwtConfig webPart (ctx: HttpContext) =
    
    let updateContextWithClaims claims =
        { ctx with userState = ctx.userState.Remove("Claims").Add("Claims", claims) }
        
    match ctx.request.header "token" with
    | Choice1Of2 accessToken ->
        let tokenValidationRequest = {
            Issuer = jwtConfig.Issuer
            SecurityKey = jwtConfig.SecurityKey
            ClientId = jwtConfig.ClientId
            AccessToken = accessToken
        }
        let validationResult = validate tokenValidationRequest
        match validationResult with
        | Choice1Of2 claims -> webPart (updateContextWithClaims claims)
        | Choice2Of2 err    -> FORBIDDEN err ctx
        
    | _ -> BAD_REQUEST "Invalid Request. Provide both ClientId and Token" ctx

let jwtAurhorize jwtConfig authorizeUser webpart =
    
    let getClaims (ctx: HttpContext) =
        let userState = ctx.userState
        if userState.ContainsKey("Claims") then
            match userState.Item "Claims" with
            | :? (Claim seq) as claims -> Some claims
            | _ -> None
        else
            None
            
    let authorize httpContext =
        match getClaims httpContext with
        | Some claims ->
            async {
                let! authorizationResult = authorizeUser claims
                match authorizationResult with
                | Authorized       -> return! webpart httpContext
                | UnAuthorized err -> return! FORBIDDEN err httpContext
            }
        | None -> FORBIDDEN "Claims not found" httpContext
        
    jwtAuthenticate jwtConfig authorize