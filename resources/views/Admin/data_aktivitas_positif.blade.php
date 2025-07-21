@extends('layouts.main_admin2')

@section('main')

<!-- halaman data aktivitas positif -->
<div class="flex flex-col gap-4">
    <h1 class="text-[2rem] text-color-1 font-bold">Data Aktivitas Positif</h1>

    <!-- tombol tambah aktivitas positif -->
    <a href="{{ route('aktivitas-positif.create') }}" class="btn flex w-fit bg-color-3 text-white text-xl font-normal">
        <img src="{{ asset('icons/Plus_white.svg') }}" alt="">
        Tambah Data
    </a>
    <!-- tombol tambah aktivitas positif -->

    <!-- tabel data -->
    <div class="w-full p-5 rounded-2xl">
        <div class="overflow-y-auto min-h-[calc(100vh-400px)]">
            <table class="table table-xs">
                <thead>
                    <tr class="text-color-1">
                        <th>No</th>
                        <th>Gambar</th>
                        <th>Nama</th>
                        <th class="text-center">Aksi</th>
                    </tr>
                </thead>

                <tbody>

                    @foreach ($aktivitasPositif as $key => $aktivitas)
                        <tr>
                            <th>{{ ($aktivitasPositif->currentPage() - 1) * $aktivitasPositif->perPage() + $key + 1 }}</th>
                            <th>
                                <div class="w-full p-3">
                                    <img src="{{ asset('storage/' . $aktivitas->gambar) }}" class="w-20 h-20 object-cover rounded-lg" />
                                </div>
                            </th>
                            <td>{{ $aktivitas->nama }}</td>
                            <td class="flex justify-center gap-2">
                                <a href="{{ route('aktivitas-positif.show', $aktivitas->id) }}" class="btn bg-blue-100 text-blue-500 border-blue-500" href="#">
                                    <img class="w-6 h-6" src="{{ asset("icons/Info.svg")}}" alt="">
                                </a>
                                <a href="{{ route('aktivitas-positif.edit', $aktivitas->id) }}" class="btn bg-green-100 text-green-500 border-green-500" href="#">
                                    <img class="w-6 h-6" src="{{ asset("icons/Edit.svg")}}" alt="">
                                </a>
                                <button class="btn bg-red-100 text-red-500 border-red-500" onclick="confirmDeletion({{ $aktivitas->id }})">
                                    <img class="w-6 h-6" src="{{ asset("icons/Waste.svg")}}" alt="">
                                </button>
                            </td>
                        </tr>

                        <form id="delete-form-{{ $aktivitas->id }}" action="{{ route('aktivitas-positif.destroy', $aktivitas->id) }}" method="POST" style="display: none;">
                            @csrf
                            @method('DELETE')
                        </form>
                    @endforeach

                </tbody>
            </table>
        </div>
    </div>

    <!-- Pagination -->
    <div class="flex justify-between border-t-[1px] bg-color-8 border-color-4 p-3">
        <span class="text-sm text-color-2 content-center">
            Menampilkan {{ $aktivitasPositif->firstItem() }} ke {{ $aktivitasPositif->lastItem() }} dari {{ $aktivitasPositif->total() }} data
        </span>

        <nav class="flex items-center gap-x-1" aria-label="Pagination">
            <!-- Tombol Previous -->
            <button type="button" 
                class="min-h-[38px] min-w-[38px] py-2 px-2.5 inline-flex justify-center items-center gap-x-2 text-sm rounded-lg border border-transparent text-color-1 hover:bg-color-5 focus:outline-none focus:bg-color-3 disabled:opacity-50 disabled:pointer-events-none"
                aria-label="Previous" {{ $aktivitasPositif->onFirstPage() ? 'disabled' : '' }}
                onclick="window.location='{{ $aktivitasPositif->previousPageUrl() }}'">
                <svg class="shrink-0 size-3.5" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="m15 18-6-6 6-6"></path>
                </svg>
                <span class="sr-only">Previous</span>
            </button>

            <div class="flex items-center gap-x-1">
                <!-- Tombol Halaman Terendah -->
                <button type="button" 
                    class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4 text-color-1 hover:bg-color-5 py-2 px-3 text-sm rounded-lg 
                    {{ $aktivitasPositif->currentPage() == 1 ? 'bg-color-3 text-color-5' : 'focus:outline-none focus:bg-color-3' }}" 
                    onclick="window.location='{{ $aktivitasPositif->url(1) }}'">1</button>
            
                <!-- Tombol Halaman Sekarang -->
                    <button type="button" 
                        class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4  bg-color-3 text-color-5 py-2 px-3 text-sm rounded-lg" 
                        disabled>Halaman {{ $aktivitasPositif->currentPage() }}</button>
            
                <!-- Tombol Halaman Tertinggi -->
                @if ($aktivitasPositif->lastPage() > 1)
                    <button type="button" 
                        class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4 text-color-1 hover:bg-color-5 py-2 px-3 text-sm rounded-lg 
                        {{ $aktivitasPositif->currentPage() == $aktivitasPositif->lastPage() ? 'bg-color-3 text-color-5' : 'focus:outline-none focus:bg-color-3' }}" 
                        onclick="window.location='{{ $aktivitasPositif->url($aktivitasPositif->lastPage()) }}'">{{ $aktivitasPositif->lastPage() }}</button>
                @endif
            </div>

            <!-- Tombol Next -->
            <button type="button" 
                class="min-h-[38px] min-w-[38px] py-2 px-2.5 inline-flex justify-center items-center gap-x-2 text-sm rounded-lg border border-transparent text-color-1 hover:bg-color-5 focus:outline-none focus:bg-color-3 disabled:opacity-50 disabled:pointer-events-none"
                aria-label="Next" {{ $aktivitasPositif->hasMorePages() ? '' : 'disabled' }}
                onclick="window.location='{{ $aktivitasPositif->nextPageUrl() }}'">
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