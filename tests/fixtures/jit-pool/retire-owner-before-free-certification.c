static unsigned ios_tail_carves_retire_owner( struct ios_tail_carve *carves, unsigned n, void *peb,
                                              time_t now, size_t *bytes, unsigned long long quiescent_lease )
{
    unsigned i, retired = 0;

    *bytes = 0;
    if (!peb) return 0;
    for (i = 0; i < n; i++)
    {
        if (carves[i].free || carves[i].peb != peb) continue;
        carves[i].free = 1;
        carves[i].retired = 1;
        carves[i].retired_lease = quiescent_lease && quiescent_lease == carves[i].allocation_lease
                                ? quiescent_lease : 0;
        carves[i].freed_at = now;
        carves[i].peb = NULL;
        *bytes += carves[i].size;
        retired++;
    }
    return retired;
}
