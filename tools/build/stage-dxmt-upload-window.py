#!/usr/bin/env python3
"""Bound real initial-data staging, including compact batches below 32 MiB.
Composes after upload/failure/admission in owned build copies; pinned DXMT is unchanged.
"""
import argparse,hashlib,json
from pathlib import Path
FILES=('src/dxmt/dxmt_resource_initializer.hpp','src/dxmt/dxmt_resource_initializer.cpp','src/d3d11/d3d11_texture_device.cpp','src/d3d11/d3d11_device.cpp')
def once(s,a,b):
 if s.count(a)!=1:raise ValueError('upload window input changed: '+a[:100])
 return s.replace(a,b,1)
CHUNKS=r'''  // All offsets are local metadata. Each chunk preserves complete format
  // blocks and rows; only the final texture edge may have a partial block.
  // No full-subresource scratch or speculative destination access is added.
  if (texture_upload_limit_ && total_bytes_needed > texture_upload_limit_) {
    static const volatile char contract[]="[texture-row-window-v1]";
    (void)contract[0];
    if (!texel_size || texture_upload_limit_ < texel_size ||
        bytes_per_row_valid < bytes_per_row_needed ||
        (depth_sub > 1 && bytes_per_image_increment < bytes_per_image_needed)) return 0;
    const size_t columns=align(width_sub,block_size)/block_size;
    const size_t rows=align(height_sub,block_size)/block_size;
    const size_t column_limit=std::min(columns,texture_upload_limit_/texel_size);
    if (!column_limit) return 0;
    const size_t row_limit=texture_upload_limit_/(column_limit*texel_size);
    for (size_t z=0;z<depth_sub;++z) {
      for (size_t y=0;y<rows;) {
        const size_t row_count=std::min(rows-y,row_limit);
        for (size_t x=0;x<columns;) {
          const size_t column_count=std::min(columns-x,column_limit);
          const size_t chunk_row=column_count*texel_size;
          const size_t chunk_bytes=chunk_row*row_count;
          bool recorded=false;
          for (unsigned retry=0;retry<2;++retry) {
            if (!prepareUploadLocked(chunk_bytes)) return 0;
            size_t offset=0;auto buffer=allocateGpuHeap(chunk_bytes,offset);
            if (!buffer) return 0;
            if (!retainAllocation(allocation)) {flushInternal();continue;}
            wmtcmd_blit_copy_from_buffer_to_texture *copy=nullptr;
            if (!allocateBlit(&copy)) {flushInternal();continue;}
            if (row_count==1 || chunk_row==bytes_per_row_increment) {
              const auto source=ptr_add(data,z*bytes_per_image_increment+y*bytes_per_row_increment+x*texel_size);
              buffer.updateContents(offset,source,chunk_bytes);
            } else for (size_t row=0;row<row_count;++row) {
              const auto source=ptr_add(data,z*bytes_per_image_increment+(y+row)*bytes_per_row_increment+x*texel_size);
              buffer.updateContents(offset+row*chunk_row,source,chunk_row);
            }
            copy->type=WMTBlitCommandCopyFromBufferToTexture;
            copy->src=buffer;copy->src_offset=offset;copy->bytes_per_row=chunk_row;
            copy->bytes_per_image=is_3d_tex ? chunk_bytes : 0;
            copy->size={uint32_t(std::min<size_t>(width_sub-x*block_size,column_count*block_size)),
                        uint32_t(std::min<size_t>(height_sub-y*block_size,row_count*block_size)),1};
            copy->dst=allocation->texture();copy->slice=slice;copy->level=level;
            copy->origin={uint32_t(x*block_size),uint32_t(y*block_size),uint32_t(z)};
            recorded=true;break;
          }
          if (!recorded) return 0;
          x+=column_count;
        }
        y+=row_count;
      }
    }
    return current_seq_id_;
  }
'''
WINDOW=r'''  // Native read-only budget uses the exact admission floor and outstanding
  // credits. It is a snapshot, never a reservation: op41 still serializes and
  // remeasures the entire destination + new staging growth before allocation.
  size_t forecastPressureUploadGrowth(size_t total, size_t first, bool compact, uint64_t destination, uint64_t own_credit=0) {
    size_t window=0;
    if (compact) {
      const auto budget=resourceGrowthBudgetSnapshot(own_credit);
      if (budget.valid) {
        const uint64_t usable=budget.available>budget.pending && budget.available-budget.pending>budget.floor ?
            budget.available-budget.pending-budget.floor : 0;
        const uint64_t spare=usable>destination ? usable-destination : 0;
        // Covers 16-KiB native pages and 64-KiB Windows allocation classes.
        // Charge the actual whole class, not a nominal byte-only window.
        constexpr size_t granularity=64u<<10;
        const size_t natural=uploadBlockSize();
        size_t maximum=granularity;
        while (maximum<natural && maximum<total) maximum*=2;
        maximum=std::min(maximum,natural);
        window=granularity;
        while (window<=maximum/2 && window<=spare/2) window*=2;
        window=std::min(window,maximum);
      }
    }
    return forecastUploadGrowth(total,first,compact,window);
  }
  size_t textureUploadWindow() const { return texture_upload_limit_; }
'''
def stage_file(name,s):
 if '[texture-row-window-v1]' in s or 'forecastPressureUploadGrowth(' in s:raise ValueError('already staged')
 if name==FILES[0]:
  s=once(s,'size_t forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes = 0, bool compact = false);','size_t forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes = 0, bool compact = false, size_t window = 0);\n'+WINDOW)
  s=once(s,'  size_t texture_upload_budget_ = 0, texture_upload_spent_ = 0;','  size_t texture_upload_limit_ = 0;\n  std::chrono::steady_clock::time_point texture_upload_wait_deadline_{};\n  size_t texture_upload_budget_ = 0, texture_upload_spent_ = 0;')
  s=once(s,'    size_t previous_, previous_budget_, previous_spent_;','    size_t previous_, previous_budget_, previous_spent_, previous_limit_;\n    std::chrono::steady_clock::time_point previous_deadline_;')
  s=once(s,'      previous_ = owner_.texture_upload_minimum_;','      previous_ = owner_.texture_upload_minimum_;\n      previous_limit_=owner_.texture_upload_limit_;previous_deadline_=owner_.texture_upload_wait_deadline_;\n      owner_.texture_upload_limit_=0;owner_.texture_upload_wait_deadline_={};')
  return once(s,'      owner_.texture_upload_minimum_ = previous_;','      owner_.texture_upload_minimum_ = previous_;\n      owner_.texture_upload_limit_=previous_limit_;owner_.texture_upload_wait_deadline_=previous_deadline_;')
 if name==FILES[1]:
  s=once(s,'ResourceInitializer::forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes, bool compact)', 'ResourceInitializer::forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes, bool compact, size_t window)')
  s=once(s,'const bool bounded = compact && total_payload_bytes > natural &&\n      first_subresource_bytes && first_subresource_bytes <= natural;','const bool bounded = compact && (window || (total_payload_bytes > natural &&\n      first_subresource_bytes && first_subresource_bytes <= natural));\n  if (!window) window=natural;\n  texture_upload_limit_=bounded ? window : 0;')
  s=once(s,'texture_upload_budget_ = bounded ? natural : 0;','texture_upload_budget_ = bounded ? gpu_command_heap_allocator.allocation_growth(\n      std::max(cached_coherent_seq_id,upload_queue_event_.signaledValue()),window,\n      kResourceInitializerGpuUploadHeapAlignment,window) : 0;')
  s=once(s,'texture_upload_minimum_ = bounded ? natural :','texture_upload_minimum_ = bounded ? window :')
  s=once(s,'    return natural;','    return texture_upload_budget_;')
  s=s.replace('texture_upload_budget_ && texture_upload_active_','texture_upload_limit_ && texture_upload_active_')
  s=s.replace('!texture_upload_budget_ &&','!texture_upload_limit_ &&').replace('if (texture_upload_budget_) {','if (texture_upload_limit_) {').replace('texture_upload_budget_ ? gpu_command_heap_allocator','texture_upload_limit_ ? gpu_command_heap_allocator').replace('if (texture_upload_budget_ &&','if (texture_upload_limit_ &&')
  s=once(s,'    upload_queue_event_.waitUntilSignaledValue(submitted, 50);',r'''    uint64_t wait_ms=50;
    if (texture_upload_limit_) {
      const auto now=std::chrono::steady_clock::now();
      if (texture_upload_wait_deadline_==std::chrono::steady_clock::time_point{})
        texture_upload_wait_deadline_=now+std::chrono::milliseconds(50);
      if (now>=texture_upload_wait_deadline_) return false;
      wait_ms=std::max<int64_t>(1,std::chrono::duration_cast<std::chrono::milliseconds>(texture_upload_wait_deadline_-now).count());
    }
    upload_queue_event_.waitUntilSignaledValue(submitted, wait_ms);''')
  # Insert after the existing lock and BEFORE any upload is linked. The base
  # initializer already computed format/decode layout, including pitches.
  marker='''  if (upload_bytes_since_flush_ &&
      upload_bytes_since_flush_ + total_bytes_needed > kResourceInitializerFlushThreshold)'''
  return once(s,marker,CHUNKS+'\n'+marker)
 if name==FILES[2]:
  # This helper is before the factory and accepts its metadata scope.
  s=once(s,'bool allocation_denied = false) {','bool allocation_denied = false, ResourceRequestEvidence *request = nullptr) {')
  s=once(s,'  const auto pressure = memoryPressureSnapshot(true);','  const auto pressure = memoryPressureSnapshot(true);\n  uint64_t released=0;')
  s=once(s,'    DynamicBuffer::TrimCompletedForQueue(queue.memoryDomain(), coherent, release_warm, nullptr, bytes);','    released += DynamicBuffer::TrimCompletedForQueue(queue.memoryDomain(), coherent, release_warm, nullptr, bytes);')
  s=once(s,'    queue.trimCompletedTransientMemory();','    released += queue.trimCompletedTransientMemory();')
  s=once(s,'  queue.initializer.trimMemoryPressure(allocation_denied || release_warm);','  released += queue.initializer.trimMemoryPressure(allocation_denied || release_warm);\n  if(request) request->reclaim(pressure.valid ? pressure.footprint : 0,released,0,pressure.sampled_ns,0);')
  s=once(s,'uint64_t bytes, Forecast &&forecast) {','uint64_t bytes, Forecast &&forecast, ResourceRequestEvidence *request = nullptr) {')
  s=s.replace('ReclaimTextureGrowth(queue, bytes, release_warm, permit.denied());','ReclaimTextureGrowth(queue, bytes, release_warm, permit.denied(),request);')
  s=s.replace('const uint64_t fresh = forecast();','const uint64_t fresh = forecast(permit.receiptToken());')
  begin=s.index('template <typename tag>\nHRESULT CreateDeviceTextureInternal(');end=s.index('\n}\n',begin)+2
  prefix,suffix=s[:begin],s[end:];s=s[begin:end]
  s=once(s,'  WMTTextureInfo info;','  ResourceRequestEvidence request(pInitialData != nullptr);\n  WMTTextureInfo info;')
  s=once(s,'  if (creation_bytes == UINT64_MAX) {','  request.describe(info,creation_bytes);\n  if (creation_bytes == UINT64_MAX) {')
  s=once(s,'PrepareTextureGrowth(pDevice, creation_permit, prospective_bytes, forecast_creation)','PrepareTextureGrowth(pDevice, creation_permit, prospective_bytes, forecast_creation,&request)')
  s=once(s,'    ReportTextureFailure(creation_permit.nativeStatus()', '    request.stage(2);request.budget(creation_permit,creation_initializer.textureUploadWindow());\n    ReportTextureFailure(creation_permit.nativeStatus()')
  s=once(s,'  bool single_subresource =', '  request.budget(creation_permit,creation_initializer.textureUploadWindow());request.stage(3);\n  bool single_subresource =')
  s=once(s,'    TextureInitializationCredit gpu_credit(', '    request.stage(4);\n    TextureInitializationCredit gpu_credit(')
  s=once(s,'    return gpu_credit.finish();','    request.gpu(initializer.event().handle,initializer.initializationFence());\n    const bool finished=gpu_credit.finish();if(!finished)request.stage(7);return finished;')
  # Explicit failure stages preserve the native nil versus admission distinction.
  s=s.replace('      ReportTextureFailure("native-nil",','      request.stage(3);\n      ReportTextureFailure("native-nil",').replace('          ReportTextureFailure("initial-upload-failed",','          request.stage(4);\n          ReportTextureFailure("initial-upload-failed",')
  s=s.replace('    *ppTexture = reinterpret_cast<typename tag::COM_IMPL *>(tex);','    request.resource(reinterpret_cast<uintptr_t>(tex));\n    *ppTexture = reinterpret_cast<typename tag::COM_IMPL *>(tex);')
  for result in ['E_INVALIDARG','E_OUTOFMEMORY','E_FAIL','S_OK']:
    s=s.replace('return '+result+';','return request.result('+result+');')
  s=once(s,'auto forecast_creation = [&]() -> uint64_t {','auto forecast_creation = [&](uint64_t own_credit=0) -> uint64_t {')
  s=once(s,'const bool compact = largest_bytes <= creation_initializer.uploadBlockSize() &&\n        memoryPressureSnapshot().needsReclaim(creation_bytes);','const bool compact = memoryPressureSnapshot().needsReclaim(creation_bytes);')
  return prefix+once(s,'creation_initializer.forecastUploadGrowth(size_t(payload), size_t(largest_bytes), compact)','creation_initializer.forecastPressureUploadGrowth(size_t(payload), size_t(largest_bytes), compact, creation_bytes, own_credit)')+suffix
 if name==FILES[3]:
  s=once(s,'#include "d3d11_device.hpp"','#include "d3d11_device.hpp"\n#include "memory_pressure.hpp"')
  a=s.index('  HRESULT STDMETHODCALLTYPE CreateShaderResourceView1(');b=s.index('\n  HRESULT STDMETHODCALLTYPE CreateUnorderedAccessView1(',a)
  body=s[a:b]
  body=once(body,'    InitReturnPtr(ppSRView);','    ResourceRequestEvidence request(false,2);request.stage(6);request.resource(reinterpret_cast<uintptr_t>(pResource));\n    InitReturnPtr(ppSRView);')
  body=body.replace('return E_INVALIDARG;','return request.result(E_INVALIDARG);').replace('return S_FALSE;','return request.result(S_FALSE);')
  body=once(body,'return static_cast<D3D11ResourceCommon *>(pResource)->CreateShaderResourceView(pDesc, ppSRView);','return request.result(static_cast<D3D11ResourceCommon *>(pResource)->CreateShaderResourceView(pDesc, ppSRView));')
  return s[:a]+body+s[b:]
 raise ValueError(name)
def main():
 p=argparse.ArgumentParser();p.add_argument('--source-dir',required=True);p.add_argument('--output-dir',required=True);p.add_argument('--overlay-dir',required=True);a=p.parse_args();records={}
 for name in FILES:
  src=Path(a.overlay_dir)/name
  if not src.is_file():src=Path(a.source_dir)/name
  text=src.read_text();out=stage_file(name,text);dest=Path(a.output_dir)/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(out)
  records[name]=hashlib.sha256(out.encode()).hexdigest()
 print(json.dumps({'stage':'texture-row-window-v1','records':records}))
if __name__=='__main__':main()
