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

static ID3DBlob *compile(compile_fn compiler, const char *entry, const char *profile)
{
    ID3DBlob *code = NULL, *errors = NULL;
    HRESULT hr = compiler(shader, sizeof(shader) - 1, "owned-pixel-probe", NULL,
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

static void initialize(void)
{
    HMODULE compiler_module = LoadLibraryW(L"d3dcompiler_47.dll");
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
    FreeLibrary(compiler_module);
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

int main(void)
{
    puts("[d3d11-pixels] begin real-api offscreen readback; successful APIs alone do not pass");
    initialize();
    texture_checks(1, DXGI_FORMAT_BC1_TYPELESS, DXGI_FORMAT_BC1_UNORM, DXGI_FORMAT_BC1_UNORM_SRGB, "BC1");
    texture_checks(3, DXGI_FORMAT_BC3_TYPELESS, DXGI_FORMAT_BC3_UNORM, DXGI_FORMAT_BC3_UNORM_SRGB, "BC3");
    texture_checks(4, DXGI_FORMAT_BC4_TYPELESS, DXGI_FORMAT_BC4_UNORM, 0, "BC4");
    texture_checks(5, DXGI_FORMAT_BC5_TYPELESS, DXGI_FORMAT_BC5_UNORM, 0, "BC5");
    texture_checks(6, DXGI_FORMAT_BC6H_TYPELESS, DXGI_FORMAT_BC6H_UF16, 0, "BC6H-zero");
    texture_checks(7, DXGI_FORMAT_BC7_TYPELESS, DXGI_FORMAT_BC7_UNORM, DXGI_FORMAT_BC7_UNORM_SRGB, "BC7-mode6");
    ID3D11DeviceContext_ClearState(context);
    ID3D11Buffer_Release(controls);
    ID3D11SamplerState_Release(sampler);
    ID3D11Query_Release(finished);
    ID3D11VertexShader_Release(vs);
    ID3D11PixelShader_Release(ps);
    ID3D11DeviceContext_Release(context);
    ID3D11Device_Release(device);
    printf("[d3d11-pixels] %s readbacks=%u failures=%u\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
