static void ios_swap_commit( void *base, size_t size, unsigned int vprot, struct file_view *view )
{
    int why;
    if (ios_swap_fd < 0) return;
    if (!ios_swap_v2) { if (ios_swap_eligible( base, size, vprot, view )) ios_swap_back( base, size, vprot ); return; }
    if ((ios_swap_wide || ios_swap_broad) && ios_swap_n && ios_swap_overlaps( base, size )) { ios_swap_note( IOS_SW_PRESENT, size ); return; }
    why = ios_swap_why( base, size, vprot, view );
    if (why == IOS_SW_BACKED) why = ios_swap_map( base, size, get_unix_prot( vprot | VPROT_COMMITTED ) );   /* ml1082 */
    ios_swap_note( why, size );
}
