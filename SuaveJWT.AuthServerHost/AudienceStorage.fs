
module AudienceStorage

open JwtToken
open System.Collections.Generic

let private audienceStorage
    = new Dictionary<string, Audience>()
    
let saveAudience (audience: Audience) =
    audienceStorage.Add(audience.ClientId, audience)
    audience |> async.Return
    
let getAudience clientId =
    if audienceStorage.ContainsKey(clientId) then
        Some audienceStorage.[clientId] |> async.Return
    else
        None |> async.Return
    
