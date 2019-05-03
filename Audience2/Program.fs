// Learn more about F# at http://fsharp.org

open System
open Encodings
open Secure

open Suave.Operators
open Suave.Successful
open Suave.Filters
open Suave.Http
open Suave.Web

open Suave
open Suave
open Suave.Http
open System.Security.Claims

[<EntryPoint>]
let main argv =
    
    let base64Key = Base64String.fromString ""
    let jwtConfig = {
        Issuer = "http://127.0.0.1:8080/suave"
        ClientId = ""
        SecurityKey = KeyStore.securityKey base64Key
    }
    
    let authorizeSuperUser (claims: Claim seq) =
        let isSuperUser (c: Claim) =
            c.Type = ClaimTypes.Role && c.Value = "SuperUser"
        match claims |> Seq.tryFind isSuperUser with
        | Some _ -> Authorized |> async.Return
        | None   -> UnAuthorized "User is not a super user" |> async.Return
        
    let authorize = jwtAurhorize jwtConfig
    let sample1 = path "/audience2/sample1" >=> OK "Sample 1"
    let sample2 = path "/audience2/sample2" >=> authorize authorizeSuperUser (OK "Sample 2")
    
    let config = { defaultConfig with bindings = [HttpBinding.createSimple HTTP "127.0.0.1" 8083] }
    let app = WebPart.choose [ sample1; sample2 ]
    
    startWebServer config app
    0 // return an integer exit code
