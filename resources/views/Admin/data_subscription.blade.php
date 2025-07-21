@extends('layouts.main_admin')

@section('main')

<!-- Halaman Data Subscription Aktif -->
<div class="flex flex-col gap-4">
    <h1 class="text-[2rem] text-color-1 font-bold">Data Subscription Aktif</h1>

    <!-- Tabel Data -->
    <div class="w-full p-5 rounded-2xl">
        <div class="overflow-y-auto min-h-[calc(100vh-350px)]">
            <table class="table table-xs">
                <thead>
                    <tr class="text-color-1">
                        <th>No</th>
                        <th>Email</th>
                        <th>Dimulai Pada</th>
                        <th>Berakhir Pada</th>
                        <th>Sisa Waktu</th>
                    </tr>
                </thead>

                <tbody>
                    @foreach ($subscriptions as $key => $subscription)
                        <tr>
                            <th>{{ ($subscriptions->currentPage() - 1) * $subscriptions->perPage() + $key + 1 }}</th>
                            <td>{{ $subscription->user->email ?? 'Tidak Diketahui' }}</td>
                            <td>{{ $subscription->started_at->format('d-m-Y H:i:s') }}</td>
                            <td>{{ $subscription->ends_at->format('d-m-Y H:i:s') }}</td>
                            <td>{{ $subscription->remaining_time }}</td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        </div>
    </div>

    <!-- Pagination -->
    <div class="flex justify-between border-t-[1px] bg-color-8 border-color-4 p-3">
        <span class="text-sm text-color-2 content-center">
            Menampilkan {{ $subscriptions->firstItem() }} ke {{ $subscriptions->lastItem() }} dari {{ $subscriptions->total() }} data
        </span>

        <nav class="flex items-center gap-x-1" aria-label="Pagination">
            <!-- Tombol Previous -->
            <button type="button" 
                class="min-h-[38px] min-w-[38px] py-2 px-2.5 inline-flex justify-center items-center gap-x-2 text-sm rounded-lg border border-transparent text-color-1 hover:bg-color-5 focus:outline-none focus:bg-color-3 disabled:opacity-50 disabled:pointer-events-none"
                aria-label="Previous" {{ $subscriptions->onFirstPage() ? 'disabled' : '' }}
                onclick="window.location='{{ $subscriptions->previousPageUrl() }}'">
                <svg class="shrink-0 size-3.5" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="m15 18-6-6 6-6"></path>
                </svg>
                <span class="sr-only">Previous</span>
            </button>

            <!-- Tombol Halaman -->
            <div class="flex items-center gap-x-1">
                <button type="button" 
                    class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4 text-color-1 hover:bg-color-5 py-2 px-3 text-sm rounded-lg 
                    {{ $subscriptions->currentPage() == 1 ? 'bg-color-3 text-color-5' : 'focus:outline-none focus:bg-color-3' }}" 
                    onclick="window.location='{{ $subscriptions->url(1) }}'">1</button>

                <button type="button" 
                    class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4  bg-color-3 text-color-5 py-2 px-3 text-sm rounded-lg" 
                    disabled>Halaman {{ $subscriptions->currentPage() }}</button>

                @if ($subscriptions->lastPage() > 1)
                    <button type="button" 
                        class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4 text-color-1 hover:bg-color-5 py-2 px-3 text-sm rounded-lg 
                        {{ $subscriptions->currentPage() == $subscriptions->lastPage() ? 'bg-color-3 text-color-5' : 'focus:outline-none focus:bg-color-3' }}" 
                        onclick="window.location='{{ $subscriptions->url($subscriptions->lastPage()) }}'">{{ $subscriptions->lastPage() }}</button>
                @endif
            </div>

            <!-- Tombol Next -->
            <button type="button" 
                class="min-h-[38px] min-w-[38px] py-2 px-2.5 inline-flex justify-center items-center gap-x-2 text-sm rounded-lg border border-transparent text-color-1 hover:bg-color-5 focus:outline-none focus:bg-color-3 disabled:opacity-50 disabled:pointer-events-none"
                aria-label="Next" {{ $subscriptions->hasMorePages() ? '' : 'disabled' }}
                onclick="window.location='{{ $subscriptions->nextPageUrl() }}'">
                <span class="sr-only">Next</span>
                <svg class="shrink-0 size-3.5" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="m9 18 6-6-6-6"></path>
                </svg>
            </button>
        </nav>
    </div>
    <!-- END Pagination -->

</div>

@endsection
