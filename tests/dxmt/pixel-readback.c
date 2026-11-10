/* Owned D3D11 regression probe. Runs the installed d3d11.dll; no mocks, window,
 * swapchain, assets, registry changes or renderer-selection overrides. */
#define COBJMACROS
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pixel-reference-vectors.h"

static ID3D11Device *device;
static ID3D11DeviceContext *context;
static ID3D11VertexShader *vs;
static ID3D11PixelShader *ps;
static ID3D11Buffer *controls;
static ID3D11SamplerState *sampler;
static ID3D11Query *finished;
static unsigned checks, failures;

static void require(HRESULT hr, const char *operation)
{
    if (FAILED(hr)) {
        printf("[d3d11-pixels] FAIL api=%s hr=%08lx\n", operation, (unsigned long)hr);
        ExitProcess(2);
    }
}

static const char shader[] =
    "cbuffer Controls : register(b0) { uint mip; uint branchMode; uint loops; uint unused; };\n"
    "Texture2DArray<float4> source : register(t0); SamplerState pointSampler : register(s0);\n"
    "float4 vertex(uint id : SV_VertexID) : SV_Position {\n"
    " float2 uv = float2((id << 1) & 2, id & 2);\n"
    " return float4(uv * float2(2,-2) + float2(-1,1), 0.5, 1); }\n"
    "float4 pixel(float4 p : SV_Position) : SV_Target {\n"
    " float4 value = source.SampleLevel(pointSampler, float3(.5,.5,0), mip);\n"
    " [branch] if (branchMode == 1) { value.rgb = value.bgr; }\n"
    " else if (branchMode == 2) { value.rgb = 1 - value.rgb; }\n"
    " [loop] for (uint i = 0; i < loops; ++i) {\n"
    "   if (i == 1) continue; if (i == 3) break; value.rgb *= .5; }\n"
    " return value; }\n";

typedef HRESULT (WINAPI *compile_fn)(const void *, SIZE_T, const char *,
    const D3D_SHADER_MACRO *, ID3DInclude *, const char *, const char *, UINT,
    UINT, ID3DBlob **, ID3DBlob **);
static HMODULE compiler_module;
static compile_fn shader_compiler;

static ID3DBlob *compile_text(compile_fn compiler, const char *text, const char *entry, const char *profile)
{
    ID3DBlob *code = NULL, *errors = NULL;
    HRESULT hr = compiler(text, strlen(text), "owned-pixel-probe", NULL,
        NULL, entry, profile, D3DCOMPILE_ENABLE_STRICTNESS | D3DCOMPILE_SKIP_OPTIMIZATION,
        0, &code, &errors);
    if (errors) {
        /* Only our fixed shader source is compiled; cap diagnostic output. */
        printf("[d3d11-pixels] compiler: %.1000s\n",
               (const char *)ID3D10Blob_GetBufferPointer(errors));
        ID3D10Blob_Release(errors);
    }
    require(hr, entry);
    return code;
}

static ID3DBlob *compile(compile_fn compiler, const char *entry, const char *profile)
{
    return compile_text(compiler, shader, entry, profile);
}

static void initialize(void)
{
    compiler_module = LoadLibraryW(L"d3dcompiler_47.dll");
    compile_fn compiler = compiler_module ?
        (compile_fn)(void *)GetProcAddress(compiler_module, "D3DCompile") : NULL;
    ID3DBlob *code;
    D3D_FEATURE_LEVEL level;
    D3D11_BUFFER_DESC buffer = {0};
    D3D11_SAMPLER_DESC sample = {0};
    D3D11_RASTERIZER_DESC raster = {0};
    D3D11_QUERY_DESC query = {D3D11_QUERY_EVENT, 0};
    ID3D11RasterizerState *raster_state;
    IUnknown *dxmt_device;
    /* This is the real pinned DXMT IMTLDXGIDevice identity. Merely asking for
     * HARDWARE on another Wine installation could otherwise test wined3d. */
    const GUID dxmt_iid = {0x6bfa1657, 0x9cb1, 0x471a, {0xa4,0xfb,0x7c,0xac,0xf8,0xa8,0x12,0x07}};
    D3D11_VIEWPORT viewport = {0, 0, 4, 4, 0, 1};
    if (!compiler) {
        puts("[d3d11-pixels] FAIL missing d3dcompiler_47!D3DCompile");
        ExitProcess(2);
    }
    shader_compiler = compiler;
    require(D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0, NULL, 0,
                             D3D11_SDK_VERSION, &device, &level, &context), "D3D11CreateDevice");
    require(ID3D11Device_QueryInterface(device, &dxmt_iid, (void **)&dxmt_device), "DXMT device identity");
    IUnknown_Release(dxmt_device);
    printf("[d3d11-pixels] device=DXMT driver=hardware feature-level=%04x pointer-bits=%u\n",
           level, (unsigned)(8 * sizeof(void *)));
    require(ID3D11Device_CreateQuery(device, &query, &finished), "CreateQuery");
    code = compile(compiler, "vertex", "vs_5_0");
    require(ID3D11Device_CreateVertexShader(device, ID3D10Blob_GetBufferPointer(code),
        ID3D10Blob_GetBufferSize(code), NULL, &vs), "CreateVertexShader");
    ID3D10Blob_Release(code);
    code = compile(compiler, "pixel", "ps_5_0");
    require(ID3D11Device_CreatePixelShader(device, ID3D10Blob_GetBufferPointer(code),
        ID3D10Blob_GetBufferSize(code), NULL, &ps), "CreatePixelShader");
    ID3D10Blob_Release(code);
    buffer.ByteWidth = 16;
    buffer.Usage = D3D11_USAGE_DEFAULT;
    buffer.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
    require(ID3D11Device_CreateBuffer(device, &buffer, NULL, &controls), "CreateBuffer");
    sample.Filter = D3D11_FILTER_MIN_MAG_MIP_POINT;
    sample.AddressU = sample.AddressV = sample.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
    sample.MaxLOD = D3D11_FLOAT32_MAX;
    require(ID3D11Device_CreateSamplerState(device, &sample, &sampler), "CreateSamplerState");
    raster.FillMode = D3D11_FILL_SOLID;
    raster.CullMode = D3D11_CULL_NONE;
    raster.DepthClipEnable = TRUE;
    require(ID3D11Device_CreateRasterizerState(device, &raster, &raster_state), "CreateRasterizerState");
    ID3D11DeviceContext_RSSetState(context, raster_state);
    ID3D11RasterizerState_Release(raster_state);
    ID3D11DeviceContext_RSSetViewports(context, 1, &viewport);
    ID3D11DeviceContext_IASetPrimitiveTopology(context, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    ID3D11DeviceContext_VSSetShader(context, vs, NULL, 0);
    ID3D11DeviceContext_PSSetShader(context, ps, NULL, 0);
    ID3D11DeviceContext_PSSetConstantBuffers(context, 0, 1, &controls);
    ID3D11DeviceContext_PSSetSamplers(context, 0, 1, &sampler);
}

static void put_bits(uint8_t *block, unsigned *position, unsigned value, unsigned count)
{
    for (unsigned i = 0; i < count; ++i, ++*position)
        block[*position / 8] |= ((value >> i) & 1) << (*position & 7);
}

/* Constant blocks with hand-computable endpoints. No DXMT decoder is used as
 * the oracle. BC7 uses valid mode 6, equal endpoints, even values, p-bits 0.
 * The all-zero BC6H mode-0 block represents RGB zero, implicit alpha one. */
static unsigned block_for(unsigned kind, unsigned alternate, uint8_t block[16], float expected[4])
{
    memset(block, 0, 16);
    expected[0] = expected[1] = expected[2] = 0;
    expected[3] = 1;
    if (kind == 1 || kind == 3) {
        unsigned color = alternate ? 0xf800 : 0x8410;
        uint8_t *rgb = block + (kind == 3 ? 8 : 0);
        rgb[0] = color & 255; rgb[1] = color >> 8;
        expected[0] = alternate ? 1 : 132 / 255.0f;
        expected[1] = alternate ? 0 : 130 / 255.0f;
        expected[2] = alternate ? 0 : 132 / 255.0f;
        if (kind == 3) {
            block[0] = block[1] = alternate ? 255 : 128;
            expected[3] = block[0] / 255.0f;
        }
        return kind == 1 ? 8 : 16;
    }
    if (kind == 4 || kind == 5) {
        block[0] = block[1] = alternate ? 255 : 128;
        expected[0] = block[0] / 255.0f;
        if (kind == 5) {
            block[8] = block[9] = alternate ? 0 : 64;
            expected[1] = block[8] / 255.0f;
        }
        return kind == 4 ? 8 : 16;
    }
    if (kind == 7) {
        unsigned position = 0;
        unsigned rgba[4] = {alternate ? 254 : 130, alternate ? 0 : 64, alternate ? 0 : 192, 254};
        put_bits(block, &position, 0x40, 7);
        for (unsigned c = 0; c < 4; ++c) {
            put_bits(block, &position, rgba[c] / 2, 7);
            put_bits(block, &position, rgba[c] / 2, 7);
            expected[c] = rgba[c] / 255.0f;
        }
        /* All remaining p-bits/indices are zero. */
    }
    return 16;
}

static float srgb_to_linear(float v)
{
    return v <= .04045f ? v / 12.92f : powf((v + .055f) / 1.055f, 2.4f);
}

static void wait_for_readback(void)
{
    ULONGLONG started = GetTickCount64();
    HRESULT hr;
    ID3D11DeviceContext_End(context, (ID3D11Asynchronous *)finished);
    ID3D11DeviceContext_Flush(context);
    while ((hr = ID3D11DeviceContext_GetData(context, (ID3D11Asynchronous *)finished,
                                           NULL, 0, D3D11_ASYNC_GETDATA_DONOTFLUSH)) == S_FALSE) {
        if (GetTickCount64() - started > 30000) {
            puts("[d3d11-pixels] FAIL GPU completion exceeded 30 seconds");
            ExitProcess(2);
        }
        Sleep(1);
    }
    require(hr, "GetData(GPU completion)");
}

static void draw_check(ID3D11ShaderResourceView *view, const char *name,
                       unsigned mip, unsigned branch, unsigned loops, const float input[4],
                       int srgb, DXGI_FORMAT target_format, unsigned state)
{
    ID3D11Texture2D *target, *readback;
    ID3D11Texture2D *depth = NULL;
    ID3D11DepthStencilView *dsv = NULL;
    ID3D11DepthStencilState *depth_state = NULL;
    ID3D11BlendState *blend = NULL;
    ID3D11RenderTargetView *rtv;
    D3D11_TEXTURE2D_DESC desc = {0};
    D3D11_MAPPED_SUBRESOURCE mapped;
    uint32_t data[4] = {mip, branch, loops, 0};
    const float clear[4] = {.125f, .25f, .375f, .5f};
    float expected[4];
    int failed = 0;
    memcpy(expected, input, sizeof(expected));
    for (unsigned c = 0; c < 3; ++c) if (srgb) expected[c] = srgb_to_linear(expected[c]);
    if (branch == 1) { float value = expected[0]; expected[0] = expected[2]; expected[2] = value; }
    if (branch == 2) for (unsigned c = 0; c < 3; ++c) expected[c] = 1 - expected[c];
    for (unsigned i = 0; i < loops; ++i) {
        if (i == 1) continue;
        if (i == 3) break;
        for (unsigned c = 0; c < 3; ++c) expected[c] *= .5f;
    }
    if (state == 1) for (unsigned c = 0; c < 3; ++c)
        expected[c] = expected[c] * expected[3] + clear[c] * (1 - expected[3]);
    if (state == 3) memcpy(expected, clear, sizeof(expected));
    desc.Width = desc.Height = 4;
    desc.MipLevels = desc.ArraySize = desc.SampleDesc.Count = 1;
    desc.Format = target_format;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET;
    require(ID3D11Device_CreateTexture2D(device, &desc, NULL, &target), "CreateTexture2D(target)");
    require(ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)target, NULL, &rtv), "CreateRenderTargetView");
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    require(ID3D11Device_CreateTexture2D(device, &desc, NULL, &readback), "CreateTexture2D(readback)");
    if (state == 1) {
        D3D11_BLEND_DESC blend_desc = {0};
        blend_desc.RenderTarget[0].BlendEnable = TRUE;
        blend_desc.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
        blend_desc.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
        blend_desc.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
        blend_desc.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
        blend_desc.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_ZERO;
        blend_desc.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
        blend_desc.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
        require(ID3D11Device_CreateBlendState(device, &blend_desc, &blend), "CreateBlendState");
    }
    if (state == 2 || state == 3) {
        D3D11_DEPTH_STENCIL_DESC depth_desc = {0};
        desc.Format = DXGI_FORMAT_D32_FLOAT;
        desc.Usage = D3D11_USAGE_DEFAULT;
        desc.CPUAccessFlags = 0;
        desc.BindFlags = D3D11_BIND_DEPTH_STENCIL;
        require(ID3D11Device_CreateTexture2D(device, &desc, NULL, &depth), "CreateTexture2D(depth)");
        require(ID3D11Device_CreateDepthStencilView(device, (ID3D11Resource *)depth, NULL, &dsv), "CreateDepthStencilView");
        depth_desc.DepthEnable = TRUE;
        depth_desc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
        depth_desc.DepthFunc = D3D11_COMPARISON_LESS;
        require(ID3D11Device_CreateDepthStencilState(device, &depth_desc, &depth_state), "CreateDepthStencilState");
        ID3D11DeviceContext_ClearDepthStencilView(context, dsv, D3D11_CLEAR_DEPTH, state == 2 ? .75f : .25f, 0);
    }
    ID3D11DeviceContext_UpdateSubresource(context, (ID3D11Resource *)controls, 0, NULL, data, 0, 0);
    ID3D11DeviceContext_OMSetRenderTargets(context, 1, &rtv, dsv);
    ID3D11DeviceContext_OMSetBlendState(context, blend, NULL, ~0u);
    ID3D11DeviceContext_OMSetDepthStencilState(context, depth_state, 0);
    ID3D11DeviceContext_ClearRenderTargetView(context, rtv, clear);
    ID3D11DeviceContext_PSSetShaderResources(context, 0, 1, &view);
    ID3D11DeviceContext_Draw(context, 3, 0);
    ID3D11DeviceContext_OMSetRenderTargets(context, 0, NULL, NULL);
    ID3D11DeviceContext_CopyResource(context, (ID3D11Resource *)readback, (ID3D11Resource *)target);
    wait_for_readback();
    require(ID3D11DeviceContext_Map(context, (ID3D11Resource *)readback, 0, D3D11_MAP_READ, 0, &mapped), "Map(readback)");
    for (unsigned y = 0; y < 4; ++y) for (unsigned x = 0; x < 4; ++x) for (unsigned c = 0; c < 4; ++c) {
        const uint8_t *row = (const uint8_t *)mapped.pData + y * mapped.RowPitch;
        float value = target_format == DXGI_FORMAT_R32G32B32A32_FLOAT ?
            ((const float *)row)[x * 4 + c] : row[x * 4 + c] / 255.0f;
        /* Allow BC hardware endpoint expansion/interpolation and RGBA8 rounding. */
        if (!isfinite(value) || fabsf(value - expected[c]) > .012f) {
            if (!failed) printf("[d3d11-pixels] FAIL case=%s mip=%u branch=%u loops=%u srgb=%d rt=%u state=%u x=%u y=%u channel=%u got=%.6f expected=%.6f\n",
                name, mip, branch, loops, srgb, target_format, state, x, y, c, value, expected[c]);
            failed = 1;
        }
    }
    ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)readback, 0);
    checks++;
    failures += failed;
    ID3D11RenderTargetView_Release(rtv);
    ID3D11Texture2D_Release(target);
    ID3D11Texture2D_Release(readback);
    if (depth_state) ID3D11DepthStencilState_Release(depth_state);
    if (dsv) ID3D11DepthStencilView_Release(dsv);
    if (depth) ID3D11Texture2D_Release(depth);
    if (blend) ID3D11BlendState_Release(blend);
}

static void texture_checks(unsigned kind, DXGI_FORMAT typeless, DXGI_FORMAT unorm,
                           DXGI_FORMAT srgb, const char *name)
{
    D3D11_TEXTURE2D_DESC desc = {0}, observed;
    D3D11_SUBRESOURCE_DATA initial[8] = {{0}};
    uint8_t payload[8][128];
    float expected[8][4];
    ID3D11Texture2D *texture;
    /* Two slices, four mips (8,4,2,1); padded block rows deliberately differ
     * from the tightly packed GPU upload. Array-major subresource indexing. */
    desc.Width = desc.Height = 8;
    desc.MipLevels = 4; desc.ArraySize = 2;
    desc.Format = typeless;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_IMMUTABLE;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    for (unsigned slice = 0; slice < 2; ++slice) for (unsigned mip = 0; mip < 4; ++mip) {
        unsigned sub = mip + slice * 4, width = 8 >> mip;
        uint8_t block[16];
        unsigned bytes = block_for(kind, (slice + mip) & 1, block, expected[sub]);
        unsigned blocks = (width + 3) / 4, pitch = blocks * bytes + 16;
        memset(payload[sub], 0xcd, sizeof(payload[sub]));
        for (unsigned y = 0; y < blocks; ++y) for (unsigned x = 0; x < blocks; ++x)
            memcpy(payload[sub] + y * pitch + x * bytes, block, bytes);
        initial[sub].pSysMem = payload[sub];
        initial[sub].SysMemPitch = pitch;
        initial[sub].SysMemSlicePitch = pitch * blocks;
    }
    require(ID3D11Device_CreateTexture2D(device, &desc, initial, &texture), name);
    ID3D11Texture2D_GetDesc(texture, &observed);
    if (observed.Width != 8 || observed.Height != 8 || observed.MipLevels != 4 || observed.ArraySize != 2 || observed.Format != typeless) {
        printf("[d3d11-pixels] FAIL case=%s logical descriptor changed\n", name); failures++;
    }
    for (unsigned color = 0; color < (srgb ? 2u : 1u); ++color) for (unsigned slice = 0; slice < 2; ++slice) {
        D3D11_SHADER_RESOURCE_VIEW_DESC view_desc = {0};
        ID3D11ShaderResourceView *view;
        view_desc.Format = color ? srgb : unorm;
        view_desc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2DARRAY;
        view_desc.Texture2DArray.MipLevels = 4;
        view_desc.Texture2DArray.FirstArraySlice = slice;
        view_desc.Texture2DArray.ArraySize = 1;
        require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, &view_desc, &view), "CreateShaderResourceView");
        for (unsigned mip = 0; mip < 4; ++mip)
            draw_check(view, name, mip, 0, 0, expected[mip + slice * 4], color, DXGI_FORMAT_R32G32B32A32_FLOAT, 0);
        /* Switch branch/loop constants and target format while reusing shaders.
         * This exercises shader variants/pipeline state and constant updates. */
        draw_check(view, name, 0, 1, 4, expected[slice * 4], color, DXGI_FORMAT_R8G8B8A8_UNORM, 0);
        draw_check(view, name, 1, 2, 0, expected[1 + slice * 4], color, DXGI_FORMAT_R32G32B32A32_FLOAT, 0);
        if (kind == 3 && !color && !slice) for (unsigned state = 1; state <= 3; ++state)
            draw_check(view, name, 0, 0, 0, expected[0], 0, DXGI_FORMAT_R32G32B32A32_FLOAT, state);
        ID3D11ShaderResourceView_Release(view);
    }
    ID3D11Texture2D_Release(texture);
    if (kind == 3) {
        ID3D11Texture2D *copy;
        ID3D11ShaderResourceView *view, *none = NULL;
        D3D11_SHADER_RESOURCE_VIEW_DESC view_desc = {0};
        uint8_t block[16];
        float updated[4];
        desc.Usage = D3D11_USAGE_DEFAULT;
        require(ID3D11Device_CreateTexture2D(device, &desc, initial, &texture), "CreateTexture2D(default)");
        require(ID3D11Device_CreateTexture2D(device, &desc, NULL, &copy), "CreateTexture2D(copy)");
        ID3D11DeviceContext_CopyResource(context, (ID3D11Resource *)copy, (ID3D11Resource *)texture);
        view_desc.Format = unorm;
        view_desc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2DARRAY;
        view_desc.Texture2DArray.MostDetailedMip = 3;
        view_desc.Texture2DArray.MipLevels = 1;
        view_desc.Texture2DArray.FirstArraySlice = 1;
        view_desc.Texture2DArray.ArraySize = 1;
        require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)copy, &view_desc, &view), "CreateShaderResourceView(tail)");
        draw_check(view, "BC3-copy-resource-tail", 0, 0, 0, expected[7], 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0);
        ID3D11DeviceContext_PSSetShaderResources(context, 0, 1, &none);
        block_for(3, 1, block, updated);
        ID3D11DeviceContext_UpdateSubresource(context, (ID3D11Resource *)texture, 7, NULL, block, 16, 0);
        ID3D11DeviceContext_CopySubresourceRegion(context, (ID3D11Resource *)copy, 7, 0, 0, 0,
                                                (ID3D11Resource *)texture, 7, NULL);
        draw_check(view, "BC3-update-copy-region-tail", 0, 0, 0, updated, 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0);
        ID3D11ShaderResourceView_Release(view);
        ID3D11Texture2D_Release(copy);
        ID3D11Texture2D_Release(texture);
    }
}

/* The baseline above intentionally keeps the 113 cases that passed on the
 * phone. These additional shaders/resources cover routes the baseline did not
 * exercise: cube views, dynamic indices, nonzero slots and real vertex fetch. */
static const char extended_shader[] =
    "cbuffer Params : register(b0) { float4 params; float4 tint; };\n"
    "cbuffer Later : register(b2) { float4 later; };\n"
    "Texture2D<float4> image : register(t0);\n"
    "Texture2DArray<float4> layers : register(t1);\n"
    "TextureCube<float4> cubeImage : register(t2);\n"
    "TextureCubeArray<float4> cubes : register(t4);\n"
    "Texture2D<float4> pass3 : register(t3); Texture2D<float4> pass7 : register(t7);\n"
    "SamplerState sampleState : register(s0);\n"
    "float4 arrayPixel(float4 p : SV_Position) : SV_Target {\n"
    " return layers.SampleLevel(sampleState, params.xyz, params.w); }\n"
    "float4 cubePixel(float4 p : SV_Position) : SV_Target {\n"
    " return cubeImage.SampleLevel(sampleState, params.xyz, params.w); }\n"
    "float4 cubeArrayPixel(float4 p : SV_Position) : SV_Target {\n"
    " return cubes.SampleLevel(sampleState, float4(params.xyz,tint.x), params.w); }\n"
    "float4 samplePixel(float4 p : SV_Position) : SV_Target {\n"
    " return image.SampleLevel(sampleState, params.xy, params.z); }\n"
    "struct Vertex { float2 position:POSITION; float2 uv:TEXCOORD0; float4 color:COLOR0; };\n"
    "struct Raster { float4 position:SV_Position; float2 uv:TEXCOORD0; float4 color:COLOR0; };\n"
    "Raster indexedVertex(Vertex input, uint instance:SV_InstanceID) {\n"
    " Raster r; r.position=float4(input.position, .5, 1);\n"
    " if (params.y != 0) r.position.x = r.position.x*.5 + (instance == 0 ? -.5 : .5);\n"
    " r.uv=input.uv; r.color=input.color*tint; return r; }\n"
    "float4 indexedPixel(Raster input) : SV_Target {\n"
    " return image.SampleLevel(sampleState,input.uv,0)*input.color; }\n"
    "float4 fillPixel(float4 p:SV_Position) : SV_Target { return later; }\n"
    "float4 pass3Pixel(float4 p:SV_Position) : SV_Target { return pass3.Load(int3(p.xy,0))*later; }\n"
    "float4 pass7Pixel(float4 p:SV_Position) : SV_Target { return pass7.Load(int3(p.xy,0))+later; }\n";

enum extra_shader { EXTRA_ARRAY, EXTRA_CUBE, EXTRA_CUBE_ARRAY, EXTRA_SAMPLE,
                    EXTRA_INDEXED, EXTRA_FILL, EXTRA_PASS3, EXTRA_PASS7, EXTRA_SHADER_COUNT };
static ID3D11PixelShader *extra_ps[EXTRA_SHADER_COUNT];
static ID3D11VertexShader *indexed_vs;
static ID3D11InputLayout *indexed_layout;
static ID3D11Buffer *extra_params, *extra_later;
static ID3D11RasterizerState *extra_raster;

struct pixel_surface {
    ID3D11Texture2D *texture;
    ID3D11RenderTargetView *rtv;
    ID3D11ShaderResourceView *srv;
};

static void extra_initialize(void)
{
    static const char *entries[EXTRA_SHADER_COUNT] = {"arrayPixel", "cubePixel", "cubeArrayPixel", "samplePixel",
        "indexedPixel", "fillPixel", "pass3Pixel", "pass7Pixel"};
    D3D11_BUFFER_DESC buffer = {0};
    D3D11_RASTERIZER_DESC raster = {0};
    D3D11_INPUT_ELEMENT_DESC elements[] = {
        {"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
        {"TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 16, D3D11_INPUT_PER_VERTEX_DATA, 0},
        {"COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 24, D3D11_INPUT_PER_VERTEX_DATA, 0}
    };
    for (unsigned i = 0; i < EXTRA_SHADER_COUNT; ++i) {
        ID3DBlob *code = compile_text(shader_compiler, extended_shader, entries[i], "ps_5_0");
        require(ID3D11Device_CreatePixelShader(device, ID3D10Blob_GetBufferPointer(code),
            ID3D10Blob_GetBufferSize(code), NULL, &extra_ps[i]), entries[i]);
        ID3D10Blob_Release(code);
    }
    ID3DBlob *code = compile_text(shader_compiler, extended_shader, "indexedVertex", "vs_5_0");
    require(ID3D11Device_CreateVertexShader(device, ID3D10Blob_GetBufferPointer(code),
        ID3D10Blob_GetBufferSize(code), NULL, &indexed_vs), "CreateVertexShader(indexed)");
    require(ID3D11Device_CreateInputLayout(device, elements, 3, ID3D10Blob_GetBufferPointer(code),
        ID3D10Blob_GetBufferSize(code), &indexed_layout), "CreateInputLayout(indexed)");
    ID3D10Blob_Release(code);
    buffer.ByteWidth = 32; buffer.Usage = D3D11_USAGE_DYNAMIC;
    buffer.BindFlags = D3D11_BIND_CONSTANT_BUFFER; buffer.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    require(ID3D11Device_CreateBuffer(device, &buffer, NULL, &extra_params), "CreateBuffer(dynamic b0)");
    buffer.ByteWidth = 16;
    require(ID3D11Device_CreateBuffer(device, &buffer, NULL, &extra_later), "CreateBuffer(dynamic b2)");
    raster.FillMode = D3D11_FILL_SOLID; raster.CullMode = D3D11_CULL_NONE; raster.DepthClipEnable = TRUE;
    require(ID3D11Device_CreateRasterizerState(device, &raster, &extra_raster), "CreateRasterizerState(extended)");
}

static void extra_base_state(void)
{
    D3D11_VIEWPORT viewport = {0, 0, 4, 4, 0, 1};
    ID3D11ShaderResourceView *none[8] = {0};
    ID3D11DeviceContext_IASetInputLayout(context, NULL);
    ID3D11DeviceContext_IASetPrimitiveTopology(context, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    ID3D11DeviceContext_VSSetShader(context, vs, NULL, 0);
    ID3D11DeviceContext_RSSetState(context, extra_raster);
    ID3D11DeviceContext_RSSetViewports(context, 1, &viewport);
    ID3D11DeviceContext_OMSetBlendState(context, NULL, NULL, ~0u);
    ID3D11DeviceContext_OMSetDepthStencilState(context, NULL, 0);
    ID3D11DeviceContext_PSSetShaderResources(context, 0, 8, none);
    ID3D11DeviceContext_PSSetSamplers(context, 0, 1, &sampler);
    ID3D11DeviceContext_PSSetConstantBuffers(context, 0, 1, &extra_params);
    ID3D11DeviceContext_PSSetConstantBuffers(context, 2, 1, &extra_later);
    ID3D11DeviceContext_VSSetConstantBuffers(context, 0, 1, &extra_params);
}

static void discard_write(ID3D11Buffer *buffer, const void *bytes, unsigned size)
{
    D3D11_MAPPED_SUBRESOURCE mapped;
    require(ID3D11DeviceContext_Map(context, (ID3D11Resource *)buffer, 0,
        D3D11_MAP_WRITE_DISCARD, 0, &mapped), "Map(dynamic discard)");
    memcpy(mapped.pData, bytes, size);
    ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)buffer, 0);
}

static void set_params(float x, float y, float z, float w, const float tint[4])
{
    float data[8] = {x, y, z, w, 1, 1, 1, 1};
    if (tint) memcpy(data + 4, tint, 16);
    discard_write(extra_params, data, sizeof(data));
}

static struct pixel_surface surface_create(void)
{
    struct pixel_surface surface = {0};
    D3D11_TEXTURE2D_DESC desc = {0};
    desc.Width = desc.Height = 4; desc.MipLevels = desc.ArraySize = desc.SampleDesc.Count = 1;
    desc.Format = DXGI_FORMAT_R32G32B32A32_FLOAT; desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
    require(ID3D11Device_CreateTexture2D(device, &desc, NULL, &surface.texture), "CreateTexture2D(pass)");
    require(ID3D11Device_CreateRenderTargetView(device, (ID3D11Resource *)surface.texture, NULL, &surface.rtv), "CreateRenderTargetView(pass)");
    require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)surface.texture, NULL, &surface.srv), "CreateShaderResourceView(pass)");
    return surface;
}

static void surface_release(struct pixel_surface *surface)
{
    if (surface->srv) ID3D11ShaderResourceView_Release(surface->srv);
    if (surface->rtv) ID3D11RenderTargetView_Release(surface->rtv);
    if (surface->texture) ID3D11Texture2D_Release(surface->texture);
    memset(surface, 0, sizeof(*surface));
}

static void surface_begin(struct pixel_surface *surface, enum extra_shader pixel)
{
    const float sentinel[4] = {-3, -3, -3, -3};
    ID3D11DeviceContext_OMSetRenderTargets(context, 1, &surface->rtv, NULL);
    ID3D11DeviceContext_ClearRenderTargetView(context, surface->rtv, sentinel);
    ID3D11DeviceContext_PSSetShader(context, extra_ps[pixel], NULL, 0);
}

static void surface_check(struct pixel_surface *surface, const char *name, const float expected[16][4])
{
    ID3D11Texture2D *readback;
    D3D11_TEXTURE2D_DESC desc;
    D3D11_MAPPED_SUBRESOURCE mapped;
    int failed = 0;
    ID3D11Texture2D_GetDesc(surface->texture, &desc);
    desc.Usage = D3D11_USAGE_STAGING; desc.BindFlags = 0; desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    require(ID3D11Device_CreateTexture2D(device, &desc, NULL, &readback), "CreateTexture2D(extended readback)");
    ID3D11DeviceContext_OMSetRenderTargets(context, 0, NULL, NULL);
    ID3D11DeviceContext_CopyResource(context, (ID3D11Resource *)readback, (ID3D11Resource *)surface->texture);
    wait_for_readback();
    require(ID3D11DeviceContext_Map(context, (ID3D11Resource *)readback, 0, D3D11_MAP_READ, 0, &mapped), "Map(extended readback)");
    for (unsigned y = 0; y < 4; ++y) for (unsigned x = 0; x < 4; ++x) for (unsigned c = 0; c < 4; ++c) {
        const float *row = (const float *)((const uint8_t *)mapped.pData + y * mapped.RowPitch);
        float value = row[x * 4 + c], want = expected[y * 4 + x][c];
        if (!isfinite(value) || fabsf(value - want) > .012f) {
            if (!failed) printf("[d3d11-pixels] FAIL case=%s x=%u y=%u channel=%u got=%.6f expected=%.6f\n", name, x, y, c, value, want);
            failed = 1;
        }
    }
    ID3D11DeviceContext_Unmap(context, (ID3D11Resource *)readback, 0);
    ID3D11Texture2D_Release(readback);
    checks++; failures += failed;
}

static void surface_constant(struct pixel_surface *surface, const char *name, const float rgba[4])
{
    float expected[16][4];
    for (unsigned i = 0; i < 16; ++i) memcpy(expected[i], rgba, 16);
    surface_check(surface, name, expected);
}

static ID3D11Texture2D *float_texture(unsigned width, unsigned mips, unsigned slices,
                                    D3D11_SUBRESOURCE_DATA *data)
{
    D3D11_TEXTURE2D_DESC desc = {0};
    ID3D11Texture2D *texture;
    desc.Width = desc.Height = width; desc.MipLevels = mips; desc.ArraySize = slices;
    desc.SampleDesc.Count = 1; desc.Format = DXGI_FORMAT_R32G32B32A32_FLOAT;
    desc.Usage = D3D11_USAGE_IMMUTABLE; desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    require(ID3D11Device_CreateTexture2D(device, &desc, data, &texture), "CreateTexture2D(float input)");
    return texture;
}

static void full_array_checks(void)
{
    float payload[9][16][4], colors[9][4];
    D3D11_SUBRESOURCE_DATA data[9] = {{0}};
    ID3D11ShaderResourceView *view, *alias;
    struct pixel_surface output = surface_create();
    for (unsigned slice = 0; slice < 3; ++slice) for (unsigned mip = 0; mip < 3; ++mip) {
        unsigned sub = slice * 3 + mip, width = 4 >> mip;
        colors[sub][0] = (slice + 1) / 4.f; colors[sub][1] = (mip + 1) / 4.f;
        colors[sub][2] = (slice + mip) / 8.f; colors[sub][3] = 1;
        for (unsigned i = 0; i < width * width; ++i) memcpy(payload[sub][i], colors[sub], 16);
        data[sub].pSysMem = payload[sub]; data[sub].SysMemPitch = width * 16;
    }
    ID3D11Texture2D *texture = float_texture(4, 3, 3, data);
    require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, NULL, &view), "CreateShaderResourceView(full array)");
    extra_base_state();
    ID3D11DeviceContext_PSSetShaderResources(context, 1, 1, &view);
    for (unsigned slice = 0; slice < 3; ++slice) for (unsigned mip = 0; mip < 3; ++mip) {
        char name[80]; snprintf(name, sizeof(name), "full-array-slice%u-mip%u", slice, mip);
        set_params(.5f, .5f, (float)slice, (float)mip, NULL);
        surface_begin(&output, EXTRA_ARRAY); ID3D11DeviceContext_Draw(context, 3, 0);
        surface_constant(&output, name, colors[slice * 3 + mip]);
    }
    D3D11_SHADER_RESOURCE_VIEW_DESC range = {0};
    range.Format = DXGI_FORMAT_R32G32B32A32_FLOAT; range.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2DARRAY;
    range.Texture2DArray.MostDetailedMip = 1; range.Texture2DArray.MipLevels = 2;
    range.Texture2DArray.FirstArraySlice = 1; range.Texture2DArray.ArraySize = 2;
    require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, &range, &alias), "CreateShaderResourceView(array range)");
    ID3D11DeviceContext_PSSetShaderResources(context, 1, 1, &alias);
    for (unsigned mip = 0; mip < 2; ++mip) {
        set_params(.5f, .5f, 1, (float)mip, NULL);
        surface_begin(&output, EXTRA_ARRAY); ID3D11DeviceContext_Draw(context, 3, 0);
        surface_constant(&output, "array-relative-slice-and-mip", colors[6 + mip + 1]);
    }
    ID3D11DeviceContext_PSSetShaderResources(context, 1, 1, &view);
    set_params(.5f, .5f, 0, 0, NULL);
    surface_begin(&output, EXTRA_ARRAY); ID3D11DeviceContext_Draw(context, 3, 0);
    surface_constant(&output, "array-view-cache-rebind", colors[0]);
    ID3D11ShaderResourceView_Release(alias); ID3D11ShaderResourceView_Release(view);
    ID3D11Texture2D_Release(texture); surface_release(&output);
}

static void cube_checks(void)
{
    static const float axes[6][3] = {{1,0,0},{-1,0,0},{0,1,0},{0,-1,0},{0,0,1},{0,0,-1}};
    uint8_t payload[24][16]; float expected[24][4];
    D3D11_SUBRESOURCE_DATA data[24] = {{0}};
    D3D11_TEXTURE2D_DESC desc = {0};
    D3D11_SHADER_RESOURCE_VIEW_DESC range = {0};
    ID3D11Texture2D *texture; ID3D11ShaderResourceView *cube, *array, *second;
    struct pixel_surface output = surface_create();
    for (unsigned c = 0; c < 2; ++c) for (unsigned face = 0; face < 6; ++face) for (unsigned mip = 0; mip < 2; ++mip) {
        unsigned sub = (c * 6 + face) * 2 + mip;
        ref_cube_color(c, face, mip, expected[sub]); ref_bc6h_constant(payload[sub], expected[sub]);
        data[sub].pSysMem = payload[sub]; data[sub].SysMemPitch = 16;
    }
    desc.Width = desc.Height = 4; desc.MipLevels = 2; desc.ArraySize = 12; desc.SampleDesc.Count = 1;
    desc.Format = DXGI_FORMAT_BC6H_TYPELESS; desc.Usage = D3D11_USAGE_IMMUTABLE;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE; desc.MiscFlags = D3D11_RESOURCE_MISC_TEXTURECUBE;
    require(ID3D11Device_CreateTexture2D(device, &desc, data, &texture), "CreateTexture2D(BC6H cube array)");
    range.Format = DXGI_FORMAT_BC6H_UF16; range.ViewDimension = D3D11_SRV_DIMENSION_TEXTURECUBE;
    range.TextureCube.MipLevels = 2;
    require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, &range, &cube), "CreateShaderResourceView(cube)");
    memset(&range, 0, sizeof(range)); range.Format = DXGI_FORMAT_BC6H_UF16;
    range.ViewDimension = D3D11_SRV_DIMENSION_TEXTURECUBEARRAY;
    range.TextureCubeArray.MipLevels = 2; range.TextureCubeArray.NumCubes = 2;
    require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, &range, &array), "CreateShaderResourceView(cube array)");
    range.TextureCubeArray.First2DArrayFace = 6; range.TextureCubeArray.NumCubes = 1;
    require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, &range, &second), "CreateShaderResourceView(second cube)");
    extra_base_state(); ID3D11DeviceContext_PSSetShaderResources(context, 2, 1, &cube);
    for (unsigned face = 0; face < 6; ++face) for (unsigned mip = 0; mip < 2; ++mip) {
        char name[80]; snprintf(name, sizeof(name), "BC6H-cube-face%u-mip%u", face, mip);
        set_params(axes[face][0], axes[face][1], axes[face][2], (float)mip, NULL);
        surface_begin(&output, EXTRA_CUBE); ID3D11DeviceContext_Draw(context, 3, 0);
        surface_constant(&output, name, expected[face * 2 + mip]);
    }
    ID3D11DeviceContext_PSSetShaderResources(context, 4, 1, &array);
    for (unsigned c = 0; c < 2; ++c) for (unsigned face = 0; face < 6; ++face) for (unsigned mip = 0; mip < 2; ++mip) {
        float tint[4] = {(float)c, 1, 1, 1}; char name[80];
        snprintf(name, sizeof(name), "BC6H-cube-array%u-face%u-mip%u", c, face, mip);
        set_params(axes[face][0], axes[face][1], axes[face][2], (float)mip, tint);
        surface_begin(&output, EXTRA_CUBE_ARRAY); ID3D11DeviceContext_Draw(context, 3, 0);
        surface_constant(&output, name, expected[(c * 6 + face) * 2 + mip]);
    }
    ID3D11DeviceContext_PSSetShaderResources(context, 4, 1, &second);
    for (unsigned mip = 0; mip < 2; ++mip) {
        float tint[4] = {0, 1, 1, 1};
        set_params(0, 0, 1, (float)mip, tint);
        surface_begin(&output, EXTRA_CUBE_ARRAY); ID3D11DeviceContext_Draw(context, 3, 0);
        surface_constant(&output, "BC6H-cube-array-first-face6", expected[(6 + 4) * 2 + mip]);
    }
    ID3D11ShaderResourceView_Release(cube); ID3D11ShaderResourceView_Release(array); ID3D11ShaderResourceView_Release(second);
    ID3D11Texture2D_Release(texture); surface_release(&output);
}

static const float quadrants[4][4] = {{1,0,0,1},{0,1,0,1},{0,0,1,1},{1,1,1,1}};

static ID3D11Texture2D *quadrant_texture(void)
{
    /* Use the commonly filterable UNORM format; a sampler regression must not
     * accidentally depend on optional RGBA32F linear-filter support. */
    static const uint8_t rgba[16] = {255,0,0,255, 0,255,0,255, 0,0,255,255, 255,255,255,255};
    D3D11_SUBRESOURCE_DATA data = {rgba, 8, 0};
    D3D11_TEXTURE2D_DESC desc = {0}; ID3D11Texture2D *texture;
    desc.Width = desc.Height = 2; desc.MipLevels = desc.ArraySize = desc.SampleDesc.Count = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM; desc.Usage = D3D11_USAGE_IMMUTABLE;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    require(ID3D11Device_CreateTexture2D(device, &desc, &data, &texture), "CreateTexture2D(quadrants)");
    return texture;
}

static ID3D11SamplerState *make_sampler(D3D11_FILTER filter, D3D11_TEXTURE_ADDRESS_MODE address,
                                       float minimum, float maximum)
{
    D3D11_SAMPLER_DESC desc = {0}; ID3D11SamplerState *state;
    desc.Filter = filter; desc.AddressU = desc.AddressV = desc.AddressW = address;
    desc.MaxAnisotropy = 8; desc.ComparisonFunc = D3D11_COMPARISON_NEVER;
    desc.MinLOD = minimum; desc.MaxLOD = maximum;
    for (unsigned c = 0; c < 4; ++c) desc.BorderColor[c] = 1;
    require(ID3D11Device_CreateSamplerState(device, &desc, &state), "CreateSamplerState(extended)");
    return state;
}

static void sampler_checks(void)
{
    struct pixel_surface output = surface_create();
    ID3D11Texture2D *texture = quadrant_texture(); ID3D11ShaderResourceView *view;
    ID3D11SamplerState *states[5] = {
        make_sampler(D3D11_FILTER_MIN_MAG_MIP_POINT, D3D11_TEXTURE_ADDRESS_CLAMP, 0, D3D11_FLOAT32_MAX),
        make_sampler(D3D11_FILTER_MIN_MAG_MIP_POINT, D3D11_TEXTURE_ADDRESS_WRAP, 0, D3D11_FLOAT32_MAX),
        make_sampler(D3D11_FILTER_MIN_MAG_MIP_LINEAR, D3D11_TEXTURE_ADDRESS_CLAMP, 0, D3D11_FLOAT32_MAX),
        make_sampler(D3D11_FILTER_MIN_MAG_MIP_POINT, D3D11_TEXTURE_ADDRESS_BORDER, 0, D3D11_FLOAT32_MAX),
        make_sampler(D3D11_FILTER_ANISOTROPIC, D3D11_TEXTURE_ADDRESS_CLAMP, 0, D3D11_FLOAT32_MAX)
    };
    static const struct { const char *name; unsigned state; float u, v, rgba[4]; } cases[] = {
        {"sampler-point-clamp", 0, -.25f, 1.25f, {0,0,1,1}},
        {"sampler-point-wrap", 1, 1.25f, -.75f, {1,0,0,1}},
        {"sampler-linear-center", 2, .5f, .5f, {.5f,.5f,.5f,1}},
        {"sampler-point-border", 3, -2, -2, {1,1,1,1}},
        /* Explicit LOD gives a deterministic bilinear reference here. This
         * checks the anisotropic sampler route, not implicit-derivative quality. */
        {"sampler-aniso-explicit-lod", 4, .5f, .5f, {.5f,.5f,.5f,1}},
        {"sampler-point-cache-rebind", 0, .25f, .25f, {1,0,0,1}}
    };
    require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, NULL, &view), "CreateShaderResourceView(sampler)");
    extra_base_state(); ID3D11DeviceContext_PSSetShaderResources(context, 0, 1, &view);
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        ID3D11DeviceContext_PSSetSamplers(context, 0, 1, &states[cases[i].state]);
        set_params(cases[i].u, cases[i].v, 0, 0, NULL);
        surface_begin(&output, EXTRA_SAMPLE); ID3D11DeviceContext_Draw(context, 3, 0);
        surface_constant(&output, cases[i].name, cases[i].rgba);
    }
    ID3D11ShaderResourceView_Release(view); ID3D11Texture2D_Release(texture);
    for (unsigned i = 0; i < 5; ++i) ID3D11SamplerState_Release(states[i]);

    float payload[3][16][4]; D3D11_SUBRESOURCE_DATA data[3] = {{0}};
    for (unsigned mip = 0; mip < 3; ++mip) {
        unsigned width = 4 >> mip;
        for (unsigned i = 0; i < width * width; ++i) memcpy(payload[mip][i], quadrants[mip], 16);
        data[mip].pSysMem = payload[mip]; data[mip].SysMemPitch = width * 16;
    }
    texture = float_texture(4, 3, 1, data);
    require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, NULL, &view), "CreateShaderResourceView(LOD clamp)");
    ID3D11DeviceContext_PSSetShaderResources(context, 0, 1, &view);
    for (unsigned i = 0; i < 2; ++i) {
        ID3D11SamplerState *clamped = make_sampler(D3D11_FILTER_MIN_MAG_MIP_POINT,
            D3D11_TEXTURE_ADDRESS_CLAMP, i ? 1 : 0, i ? 2 : 0);
        ID3D11DeviceContext_PSSetSamplers(context, 0, 1, &clamped);
        set_params(.5f, .5f, i ? 0 : 2, 0, NULL);
        surface_begin(&output, EXTRA_SAMPLE); ID3D11DeviceContext_Draw(context, 3, 0);
        surface_constant(&output, i ? "sampler-MinLOD" : "sampler-MaxLOD", quadrants[i]);
        ID3D11SamplerState_Release(clamped);
    }
    ID3D11ShaderResourceView_Release(view); ID3D11Texture2D_Release(texture); surface_release(&output);
}

struct indexed_vertex { float position[2]; uint32_t padding[2]; float uv[2], color[4]; };

static void indexed_expected(float expected[16][4], const float color[4], int instanced)
{
    for (unsigned y = 0; y < 4; ++y) for (unsigned x = 0; x < 4; ++x) {
        unsigned tex_x = instanced ? x & 1 : x / 2, tex_y = y / 2;
        for (unsigned c = 0; c < 4; ++c)
            expected[y * 4 + x][c] = quadrants[tex_y * 2 + tex_x][c] * color[c];
    }
}

static void indexed_checks(void)
{
    struct indexed_vertex vertices[6] = {
        {{5,5},{0,0},{0,0},{0,0,0,0}},
        {{-1,1},{0xdeadbeef,0xcafebabe},{0,0},{1,1,1,1}},
        {{1,1},{0xdeadbeef,0xcafebabe},{1,0},{1,1,1,1}},
        {{-1,-1},{0xdeadbeef,0xcafebabe},{0,1},{1,1,1,1}},
        {{1,-1},{0xdeadbeef,0xcafebabe},{1,1},{1,1,1,1}},
        {{5,5},{0,0},{0,0},{0,0,0,0}}
    };
    const uint16_t indices16[] = {999,999,0,1,2,2,1,3};
    const uint32_t indices32[] = {999,999,0,2,1,2,3,1};
    D3D11_BUFFER_DESC desc = {0}; D3D11_SUBRESOURCE_DATA initial = {0};
    ID3D11Buffer *vb, *ib16, *ib32;
    ID3D11Texture2D *texture = quadrant_texture(); ID3D11ShaderResourceView *view;
    struct pixel_surface output = surface_create(); float expected[16][4];
    const float white[4] = {1,1,1,1}, tint[4] = {.25f,.5f,.75f,1};
    UINT stride = sizeof(vertices[0]), offset = 0;
    desc.ByteWidth = sizeof(vertices); desc.Usage = D3D11_USAGE_DYNAMIC;
    desc.BindFlags = D3D11_BIND_VERTEX_BUFFER; desc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    initial.pSysMem = vertices;
    require(ID3D11Device_CreateBuffer(device, &desc, &initial, &vb), "CreateBuffer(dynamic vertices)");
    desc.Usage = D3D11_USAGE_IMMUTABLE; desc.CPUAccessFlags = 0; desc.BindFlags = D3D11_BIND_INDEX_BUFFER;
    desc.ByteWidth = sizeof(indices16); initial.pSysMem = indices16;
    require(ID3D11Device_CreateBuffer(device, &desc, &initial, &ib16), "CreateBuffer(indices16)");
    desc.ByteWidth = sizeof(indices32); initial.pSysMem = indices32;
    require(ID3D11Device_CreateBuffer(device, &desc, &initial, &ib32), "CreateBuffer(indices32)");
    require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, NULL, &view), "CreateShaderResourceView(indexed)");
    extra_base_state(); ID3D11DeviceContext_PSSetShaderResources(context, 0, 1, &view);
    ID3D11DeviceContext_IASetInputLayout(context, indexed_layout);
    ID3D11DeviceContext_IASetVertexBuffers(context, 0, 1, &vb, &stride, &offset);
    ID3D11DeviceContext_IASetIndexBuffer(context, ib16, DXGI_FORMAT_R16_UINT, 4);
    ID3D11DeviceContext_VSSetShader(context, indexed_vs, NULL, 0);
    set_params(0, 0, 0, 0, white);
    surface_begin(&output, EXTRA_INDEXED); ID3D11DeviceContext_DrawIndexed(context, 6, 0, 1);
    indexed_expected(expected, white, 0); surface_check(&output, "indexed16-basevertex-and-index-offset", expected);
    offset = sizeof(vertices[0]);
    ID3D11DeviceContext_IASetVertexBuffers(context, 0, 1, &vb, &stride, &offset);
    ID3D11DeviceContext_IASetIndexBuffer(context, ib32, DXGI_FORMAT_R32_UINT, 4);
    set_params(0, 0, 0, 0, tint);
    surface_begin(&output, EXTRA_INDEXED); ID3D11DeviceContext_DrawIndexed(context, 6, 1, 0);
    indexed_expected(expected, tint, 0); surface_check(&output, "indexed32-vertex-offset-start-index-CB-discard", expected);
    for (unsigned i = 1; i <= 4; ++i) for (unsigned c = 0; c < 3; ++c) vertices[i].color[c] = .5f;
    discard_write(vb, vertices, sizeof(vertices));
    set_params(0, 0, 0, 0, white);
    surface_begin(&output, EXTRA_INDEXED); ID3D11DeviceContext_DrawIndexed(context, 6, 1, 0);
    const float half[4] = {.5f,.5f,.5f,1};
    indexed_expected(expected, half, 0); surface_check(&output, "indexed-vertex-WRITE_DISCARD", expected);
    set_params(0, 1, 0, 0, white);
    surface_begin(&output, EXTRA_INDEXED); ID3D11DeviceContext_DrawIndexedInstanced(context, 6, 2, 1, 0, 0);
    indexed_expected(expected, half, 1); surface_check(&output, "indexed-instanced-two-viewports-in-shader", expected);
    ID3D11Buffer_Release(vb); ID3D11Buffer_Release(ib16); ID3D11Buffer_Release(ib32);
    ID3D11ShaderResourceView_Release(view); ID3D11Texture2D_Release(texture); surface_release(&output);
}

static void multipass_checks(void)
{
    struct pixel_surface first = surface_create(), second = surface_create();
    static const float colors[2][4] = {{.5f,.25f,.75f,1},{.125f,.5f,.25f,.5f}};
    static const float operation[2][4] = {{.5f,2,.25f,1},{.25f,.125f,.5f,.25f}};
    ID3D11ShaderResourceView *none[8] = {0};
    for (unsigned round = 0; round < 2; ++round) {
        float expected[4];
        if (round) ID3D11DeviceContext_ClearState(context);
        extra_base_state();
        discard_write(extra_later, colors[round], 16);
        surface_begin(&first, EXTRA_FILL); ID3D11DeviceContext_Draw(context, 3, 0);
        /* Move the resource from RTV to SRV, at t3/t7, and update b2 without
         * flushing. Both passes' readbacks independently detect wrong CB reuse. */
        surface_begin(&second, round ? EXTRA_PASS7 : EXTRA_PASS3);
        ID3D11DeviceContext_PSSetShaderResources(context, round ? 7 : 3, 1, &first.srv);
        discard_write(extra_later, operation[round], 16);
        ID3D11DeviceContext_Draw(context, 3, 0);
        for (unsigned c = 0; c < 4; ++c) expected[c] = round ? colors[round][c] + operation[round][c]
                                                                     : colors[round][c] * operation[round][c];
        surface_constant(&first, round ? "multipass-ClearState-CB-snapshot" : "multipass-b2-CB-snapshot", colors[round]);
        surface_constant(&second, round ? "multipass-RTV-to-t7-cache-reuse" : "multipass-RTV-to-t3", expected);
        ID3D11DeviceContext_PSSetShaderResources(context, 0, 8, none);
    }
    const float color[4] = {.25f,.5f,.75f,1}, add[4] = {.25f,.125f,0,0};
    const float expected[4] = {.5f,.625f,.75f,1};
    discard_write(extra_later, color, 16);
    surface_begin(&first, EXTRA_FILL); ID3D11DeviceContext_Draw(context, 3, 0);
    surface_begin(&second, EXTRA_PASS7);
    ID3D11DeviceContext_PSSetShaderResources(context, 7, 1, &first.srv);
    /* Once bound, the context/recorded work must keep the SRV and its resource
     * alive after every application reference has been released. */
    surface_release(&first);
    discard_write(extra_later, add, 16); ID3D11DeviceContext_Draw(context, 3, 0);
    surface_constant(&second, "multipass-bound-SRV-resource-lifetime", expected);
    for (unsigned round = 0; round < 4; ++round) {
        float pixels[16][4], rgba[4] = {round / 4.f, (4 - round) / 4.f, .5f, 1};
        for (unsigned i = 0; i < 16; ++i) memcpy(pixels[i], rgba, 16);
        D3D11_SUBRESOURCE_DATA data = {pixels, 64, 0};
        ID3D11Texture2D *texture = float_texture(4, 1, 1, &data); ID3D11ShaderResourceView *view;
        require(ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)texture, NULL, &view), "CreateShaderResourceView(lifetime rebind)");
        surface_begin(&second, EXTRA_PASS3);
        ID3D11DeviceContext_PSSetShaderResources(context, 3, 1, &view);
        ID3D11ShaderResourceView_Release(view); ID3D11Texture2D_Release(texture);
        const float identity[4] = {1,1,1,1}; discard_write(extra_later, identity, 16);
        ID3D11DeviceContext_Draw(context, 3, 0);
        surface_constant(&second, "resource-lifetime-and-view-rebind-cache", rgba);
    }
    ID3D11DeviceContext_PSSetShaderResources(context, 0, 8, none);
    surface_release(&second);
}

static void suite_result(const char *name, unsigned before, unsigned failed_before)
{
    printf("[d3d11-pixels] suite=%s readbacks=%u failures=%u\n", name, checks - before, failures - failed_before);
}

int main(void)
{
    puts("[d3d11-pixels] begin real-api offscreen readback; successful APIs alone do not pass");
    puts("[d3d11-pixels] contract=extended-v2 expected-readbacks=184 baseline=113");
    initialize();
    texture_checks(1, DXGI_FORMAT_BC1_TYPELESS, DXGI_FORMAT_BC1_UNORM, DXGI_FORMAT_BC1_UNORM_SRGB, "BC1");
    texture_checks(3, DXGI_FORMAT_BC3_TYPELESS, DXGI_FORMAT_BC3_UNORM, DXGI_FORMAT_BC3_UNORM_SRGB, "BC3");
    texture_checks(4, DXGI_FORMAT_BC4_TYPELESS, DXGI_FORMAT_BC4_UNORM, 0, "BC4");
    texture_checks(5, DXGI_FORMAT_BC5_TYPELESS, DXGI_FORMAT_BC5_UNORM, 0, "BC5");
    texture_checks(6, DXGI_FORMAT_BC6H_TYPELESS, DXGI_FORMAT_BC6H_UF16, 0, "BC6H-zero");
    texture_checks(7, DXGI_FORMAT_BC7_TYPELESS, DXGI_FORMAT_BC7_UNORM, DXGI_FORMAT_BC7_UNORM_SRGB, "BC7-mode6");
    if (checks != 113) { puts("[d3d11-pixels] FAIL baseline readback count"); failures++; }
    suite_result("baseline-bc", 0, 0);
    extra_initialize();
    unsigned before = checks, failed_before = failures;
    full_array_checks(); suite_result("full-array-and-relative-mips", before, failed_before);
    before = checks; failed_before = failures;
    cube_checks(); suite_result("BC6H-colored-cube-array", before, failed_before);
    before = checks; failed_before = failures;
    sampler_checks(); suite_result("sampler-filter-address-LOD", before, failed_before);
    before = checks; failed_before = failures;
    indexed_checks(); suite_result("vertex-index-instance-discard", before, failed_before);
    before = checks; failed_before = failures;
    multipass_checks(); suite_result("multipass-binding-lifetime-cache", before, failed_before);
    if (checks != 184) { puts("[d3d11-pixels] FAIL extended readback count"); failures++; }
    ID3D11DeviceContext_ClearState(context);
    ID3D11Buffer_Release(controls);
    ID3D11SamplerState_Release(sampler);
    ID3D11Query_Release(finished);
    ID3D11VertexShader_Release(vs);
    ID3D11PixelShader_Release(ps);
    for (unsigned i = 0; i < EXTRA_SHADER_COUNT; ++i) ID3D11PixelShader_Release(extra_ps[i]);
    ID3D11VertexShader_Release(indexed_vs); ID3D11InputLayout_Release(indexed_layout);
    ID3D11Buffer_Release(extra_params); ID3D11Buffer_Release(extra_later); ID3D11RasterizerState_Release(extra_raster);
    FreeLibrary(compiler_module);
    ID3D11DeviceContext_Release(context);
    ID3D11Device_Release(device);
    printf("[d3d11-pixels] %s readbacks=%u failures=%u\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
