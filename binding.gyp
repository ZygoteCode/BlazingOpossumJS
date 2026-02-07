{
  "targets": [
    {
      "target_name": "blazing_opossum",
      "sources": [ "BlazingOpossum.cpp" ],
      "include_dirs": [ "<!@(node -p \"require('node-addon-api').include\")" ],
      "msvs_settings": {
        "VCCLCompilerTool": { 
          "AdditionalOptions": [ "/arch:AVX2", "/O2", "/Oi" ],
          "ExceptionHandling": 1
        }
      },
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ]
    }
  ]
}