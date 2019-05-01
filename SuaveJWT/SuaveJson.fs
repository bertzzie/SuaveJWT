module SuaveJson

open Newtonsoft.Json
open Newtonsoft.Json.Serialization

open Suave
open Suave.Operators
open Suave.Successful

let JSON v =
    let settings = new JsonSerializerSettings()
    settings.ContractResolver
        <- new CamelCasePropertyNamesContractResolver()
    JsonConvert.SerializeObject(v, settings)
    |> OK
    >=> Writers.setMimeType "application/json; charset=utf-8"

let mapJsonPayload<'a> (req: HttpRequest) =
    let fromJson json =
        try
            JsonConvert.DeserializeObject(json, typeof<'a>)
            :?> 'a
            |> Some
        with
        | _ -> None
        
    let getString (rawForm: byte[]) =
        System.Text.Encoding.UTF8.GetString(rawForm)
        
    req.rawForm |> getString |> fromJson
