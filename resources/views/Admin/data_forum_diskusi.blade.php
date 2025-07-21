@extends('layouts.main_admin2')

@section('main')

<!-- halaman data admin -->
<div class="flex flex-col gap-4">
    <h1 class="text-[2rem] text-color-1 font-bold">Data Forum Diskusi</h1>

    <!-- tabel data -->
    <div class="w-full p-5 rounded-2xl">
        <div class="overflow-y-auto min-h-[calc(100vh-350px)]">
            <table class="table table-xs">
                <thead>
                    <tr class="text-color-1">
                        <th>No</th>
                        <th>Perilis</th>
                        <th>Judul</th>
                        <th>Isi</th>
                        <th>Tanggal Dibuat</th>
                        <th class="text-center">Aksi</th>
                    </tr>
                </thead>

                <tbody>

                    @foreach ($diskusis as $key => $diskusi)
                        <tr>
                            <th>{{ ($diskusis->currentPage() - 1) * $diskusis->perPage() + $key + 1 }}</th>
                            <td>{{ $diskusi->pasien ? $diskusi->pasien->user->email ?? '#userDeleted' : '#userDeleted' }}</td>
                            <td class="truncate max-w-10">{{ $diskusi->judul }}</td>
                            <td class="truncate max-w-10">{{ $diskusi->isi }}</td>
                            <td>{{ $diskusi->created_at }}</td>
                            <td class="flex justify-center gap-2">
                                <a href="{{ route('diskusi.show', $diskusi->id) }}" class="btn bg-blue-100 text-blue-500 border-blue-500" href="#">
                                    <img class="w-6 h-6" src="{{ asset("icons/Info.svg")}}" alt="">
                                </a>
                                <a href="{{ route('diskusi.showBalasan', $diskusi->id) }}" class="btn bg-gray-100 text-gray-500 border-gray-500" href="#">
                                    <img class="w-6 h-6" src="{{ asset("icons/response.svg")}}" alt="">
                                </a>
                                <button class="btn bg-red-100 text-red-500 border-red-500" onclick="confirmDeletion({{ $diskusi->id }})">
                                    <img class="w-6 h-6" src="{{ asset("icons/Waste.svg")}}" alt="">
                                </button>
                            </td>
                        </tr>

                        <form id="delete-form-{{ $diskusi->id }}" action="{{ route('diskusi.destroy', $diskusi->id) }}" method="POST">
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
            Menampilkan {{ $diskusis->firstItem() }} ke {{ $diskusis->lastItem() }} dari {{ $diskusis->total() }} data
        </span>

        <nav class="flex items-center gap-x-1" aria-label="Pagination">
            <!-- Tombol Previous -->
            <button type="button" 
                class="min-h-[38px] min-w-[38px] py-2 px-2.5 inline-flex justify-center items-center gap-x-2 text-sm rounded-lg border border-transparent text-color-1 hover:bg-color-5 focus:outline-none focus:bg-color-3 disabled:opacity-50 disabled:pointer-events-none"
                aria-label="Previous" {{ $diskusis->onFirstPage() ? 'disabled' : '' }}
                onclick="window.location='{{ $diskusis->previousPageUrl() }}'">
                <svg class="shrink-0 size-3.5" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="m15 18-6-6 6-6"></path>
                </svg>
                <span class="sr-only">Previous</span>
            </button>

            <div class="flex items-center gap-x-1">
                <!-- Tombol Halaman Terendah -->
                <button type="button" 
                    class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4 text-color-1 hover:bg-color-5 py-2 px-3 text-sm rounded-lg 
                    {{ $diskusis->currentPage() == 1 ? 'bg-color-3 text-color-5' : 'focus:outline-none focus:bg-color-3' }}" 
                    onclick="window.location='{{ $diskusis->url(1) }}'">1</button>
            
                <!-- Tombol Halaman Sekarang -->
                    <button type="button" 
                        class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4  bg-color-3 text-color-5 py-2 px-3 text-sm rounded-lg" 
                        disabled>Halaman {{ $diskusis->currentPage() }}</button>
            
                <!-- Tombol Halaman Tertinggi -->
                @if ($diskusis->lastPage() > 1)
                    <button type="button" 
                        class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4 text-color-1 hover:bg-color-5 py-2 px-3 text-sm rounded-lg 
                        {{ $diskusis->currentPage() == $diskusis->lastPage() ? 'bg-color-3 text-color-5' : 'focus:outline-none focus:bg-color-3' }}" 
                        onclick="window.location='{{ $diskusis->url($diskusis->lastPage()) }}'">{{ $diskusis->lastPage() }}</button>
                @endif
            </div>

            <!-- Tombol Next -->
            <button type="button" 
                class="min-h-[38px] min-w-[38px] py-2 px-2.5 inline-flex justify-center items-center gap-x-2 text-sm rounded-lg border border-transparent text-color-1 hover:bg-color-5 focus:outline-none focus:bg-color-3 disabled:opacity-50 disabled:pointer-events-none"
                aria-label="Next" {{ $diskusis->hasMorePages() ? '' : 'disabled' }}
                onclick="window.location='{{ $diskusis->nextPageUrl() }}'">
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