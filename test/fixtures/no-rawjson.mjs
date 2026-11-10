// Preload for CI: run the tests as on a runtime without JSON.rawJSON (the fallback path of parseJson).
delete JSON.rawJSON;
delete JSON.isRawJSON;
