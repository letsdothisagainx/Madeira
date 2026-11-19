/* Frozen actual staged forecast functions from tested Madeira a99940fb.
 * Class qualification alone changes to place the old helper beside its replacement. */
size_t
LegacyInitializer::forecastUploadGrowth(size_t total_payload_bytes, size_t first_subresource_bytes, bool compact) {
  if (!total_payload_bytes)
    return 0;
  std::lock_guard<dxmt::mutex> lock(mutex_);
  if (total_payload_bytes > SIZE_MAX - (kResourceInitializerGpuUploadHeapAlignment - 1))
    return SIZE_MAX;
  texture_upload_minimum_ = compact ? align(total_payload_bytes, kResourceInitializerGpuUploadHeapAlignment) : 0;
  const uint64_t completed = std::max(cached_coherent_seq_id, upload_queue_event_.signaledValue());
  return gpu_command_heap_allocator.batch_growth(
      completed, total_payload_bytes, first_subresource_bytes ? first_subresource_bytes : total_payload_bytes,
      kResourceInitializerGpuUploadHeapAlignment, texture_upload_minimum_);
}
uint64_t legacy_factory_charge(LegacyInitializer &creation_initializer) {
 auto info=matching_layout();const bool admission_native_bc=true;
 const uint64_t creation_bytes=mem_census_texture_bytes(info,true);
 const void*pInitialData=reinterpret_cast<void*>(1);
  auto forecast_creation = [&]() -> uint64_t {
  WMTTextureInfo largest = info;
  largest.mipmap_level_count = largest.array_length = largest.sample_count = 1;
  if (largest.type == WMTTextureTypeCube || largest.type == WMTTextureTypeCubeArray)
    largest.type = WMTTextureType2D;
  const uint64_t largest_bytes = mem_census_texture_bytes(largest, admission_native_bc);
  uint64_t temporary_bytes = 0;
  if (pInitialData) {
    uint64_t subresources = mem_census_capacity_mul(info.mipmap_level_count, info.array_length);
    if (info.type == WMTTextureTypeCube || info.type == WMTTextureTypeCubeArray)
      subresources = mem_census_capacity_mul(subresources, 6);
    const uint64_t padding = mem_census_capacity_mul(subresources, 255);
    if (padding > UINT64_MAX - creation_bytes || creation_bytes + padding > SIZE_MAX)
      return UINT64_MAX;
    const uint64_t payload = creation_bytes + padding;
    // Admission and the real allocator share this batch minimum. Under
    // physical pressure a tiny immutable texture must not require a fresh
    // natural 32 MiB upload block merely to transfer a few aligned KiB.
    // Existing completed/tail backing is still reusable at no new charge.
    // This cached sample selects a block policy only. Admission still samples
    // fresh native headroom, and a denial refreshes it before reforecasting.
    // Stay within the initializer's existing natural upload capacity. A very
    // large mip/array batch retains the old chunked path rather than asking
    // Metal for a new monolithic buffer above its supported buffer length.
    const bool compact = payload <= kResourceInitializerGpuUploadHeapSize &&
        memoryPressureSnapshot().needsReclaim(creation_bytes);
    temporary_bytes = creation_initializer.forecastUploadGrowth(size_t(payload), size_t(largest_bytes), compact);
    // Natural-size batching can waste tails at rotations. Its existing
    // conservative allowance remains. Compact mode gives every new block
    // room for the entire aligned batch, so it needs no duplicate payload
    // allowance even when the first subresource used an older block's tail.
    if (!compact && temporary_bytes && payload > (uint64_t{4} << 20)) {
      if (payload > UINT64_MAX - temporary_bytes) return UINT64_MAX;
      temporary_bytes += payload;
    }
    if (!admission_native_bc && mem_census_bc_block_bytes(info.pixel_format)) {
      if (largest_bytes > UINT64_MAX - temporary_bytes) return UINT64_MAX;
      temporary_bytes += largest_bytes; // Actual fallback decode scratch, absent on native BC devices.
    }
  } else if (!(info.usage & WMTTextureUsageRenderTarget)) {
    if (largest_bytes > SIZE_MAX) return UINT64_MAX;
    temporary_bytes = creation_initializer.forecastZeroGrowth(size_t(largest_bytes));
  }
  if (temporary_bytes > UINT64_MAX - creation_bytes) return UINT64_MAX;
  return creation_bytes + temporary_bytes;
  };
 return forecast_creation();
}
