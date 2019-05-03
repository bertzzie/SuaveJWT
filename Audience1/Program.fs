// Learn more about F# at http://fsharp.org

open Encodings
open Secure

open Suave.Operators
open Suave.Successful
open Suave.Filters
open Suave.Http
open Suave.Web

open Suave
open System.Security.Claims

[<EntryPoint>]
let main argv =
    
    let base64Key =
        Base64String.fromString "sDYyUn6P8AxPZviBTKQj4rsBbubr6hqpc0-JHk8ski0"
    let jwtConfig = {
        Issuer = "http://127.0.0.1:8080/suave"
        ClientId = "b0f93cfa4854410c8027047b29989066"
        SecurityKey = KeyStore.securityKey base64Key
    }
    
    let authorizeAdmin (claims: Claim seq) =
        let isAdmin (c: Claim) =
            c.Type = ClaimTypes.Role && c.Value = "Admin"
        match claims |> Seq.tryFind isAdmin with
        | Some _ -> Authorized |> async.Return
        | None   -> UnAuthorized "User is not an admin" |> async.Return
    
    let sample1 =
        path "/audience1/sample1"
        >=> jwtAuthenticate jwtConfig (OK "Sample 1")
        
    let sample2 =
         path "/audience1/sample2"
         >=> jwtAurhorize jwtConfig authorizeAdmin (OK "Sample 2")
        
    let config = { defaultConfig with bindings = [HttpBinding.createSimple HTTP "127.0.0.1" 8081] }
    let app = WebPart.choose [ sample1; sample2 ]
    
    startWebServer config app
    0 // return an integer exit code
