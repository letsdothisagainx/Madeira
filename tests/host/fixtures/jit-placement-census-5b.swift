// Literal 5b20ed22 census and size helper; the test supplies Mach boundaries.
enum BeforePlacement {
    private static func poolRunSize(available: vm_address_t, wanted: vm_address_t,
                                    pageFit: Bool) -> vm_address_t {
        let granule: vm_address_t = pageFit ? 0x4000 : 16 << 20
        let request: vm_address_t
        if pageFit {
            request = wanted & ~(granule - 1)
        } else {
            guard wanted <= vm_address_t.max - (granule - 1) else { return 0 }
            request = (wanted + granule - 1) & ~(granule - 1)
        }
        return min(available & ~(granule - 1), request)
    }
    static func fit(wanted: UInt) -> UInt {
        let goodLow = 0x119000000
        let guestLo = 0x7000000000
            var holes: [(base: vm_address_t, size: vm_address_t)] = []
            var addr = vm_address_t(goodLow)
            var prevEnd = vm_address_t(goodLow)
            while addr < vm_address_t(guestLo) {
                var rsize: vm_size_t = 0
                var info = vm_region_basic_info_data_64_t()
                var cnt = mach_msg_type_number_t(MemoryLayout<vm_region_basic_info_data_64_t>.size / MemoryLayout<Int32>.size)
                var obj: mach_port_t = 0
                let kr = withUnsafeMutablePointer(to: &info) {
                    $0.withMemoryRebound(to: Int32.self, capacity: Int(cnt)) {
                        vm_region_64(mach_task_self_, &addr, &rsize, VM_REGION_BASIC_INFO_64, $0, &cnt, &obj)
                    }
                }
                if kr != KERN_SUCCESS { break }
                let start = min(addr, vm_address_t(guestLo))
                if start > prevEnd && start - prevEnd >= 64 << 20 { holes.append((prevEnd, start - prevEnd)) }
                prevEnd = max(prevEnd, addr + vm_address_t(rsize))
                addr = prevEnd
            }
            let desc = holes.map { String(format: "0x%lx+%luMB", Int($0.base), Int($0.size >> 20)) }.joined(separator: " ")
            LogStore.shared.log("ml1036: free holes >=64MB in [0x119000000,0x7000000000) with the window held: "
                + (desc.isEmpty ? "NONE" : desc))
            let largest = holes.map { $0.size }.max() ?? 0
        return poolRunSize(available: largest, wanted: wanted, pageFit: false)
    }
}
