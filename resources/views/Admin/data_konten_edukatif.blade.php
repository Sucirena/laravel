@extends('layouts.main_admin2')

@section('main')

<!-- halaman data konten edukatif -->
<div class="flex flex-col gap-6">
    <h1 class="text-[2rem] text-color-1 font-bold">Data Konten Edukatif</h1>

    <!-- tombol tambah data konten edukatif-->
    <a href="{{ route('konten-edukatif.create') }}" class="btn w-fit bg-color-3 text-white text-xl font-normal">
        <img src="{{ asset('icons/Plus_white.svg') }}" alt="">
        Tambah Data
    </a>
    <!-- tombol tambah data konten edukatif-->

    <!-- tabel data-->
    <div class="w-full px-5 rounded-2xl">
        <div class="overflow-y-scroll min-h-[calc(100vh-300px)]">
            <table class="table table-xs">

                <thead>
                    <tr class="text-color-1">
                        <th>No</th>
                        <th>Thumbnail</th>
                        <th>Perilis</th>
                        <th>Judul</th>
                        <th>Tipe</th>
                        <th class="text-center">Action</th>
                    </tr>
                </thead>

                <tbody>

                    @foreach ($kontenEdukatif as $key => $konten)
                        <tr>
                            <th>{{ ($kontenEdukatif->currentPage() - 1) * $kontenEdukatif->perPage() + $key + 1 }}</th>
                            <th>
                                <div class="avatar">
                                    <div class="w-9 rounded-full">
                                        <img src="{{ asset('storage/' . $konten->thumbnail) }}" />
                                    </div>
                                </div>
                            </th>
                            <td>{{ $konten->user->nama }}</td>
                            <td>{{ $konten->judul }}</td>
                            <td>{{ $konten->tipe }}</td>
                            <td class="flex justify-center gap-2">
                                <a href="{{ route('konten-edukatif.show', $konten->id) }}" class="btn bg-blue-100 text-blue-500 border-blue-500" href="#">
                                    <img class="w-6 h-6" src="{{ asset("icons/Info.svg")}}" alt="">
                                </a>
                                <a href="{{ route('konten-edukatif.edit', $konten->id) }}" class="btn bg-green-100 text-green-500 border-green-500" href="#">
                                    <img class="w-6 h-6" src="{{ asset("icons/Edit.svg")}}" alt="">
                                </a>
                                <button class="btn bg-red-100 text-red-500 border-red-500" onclick="confirmDeletion({{ $konten->id }})">
                                    <img class="w-6 h-6" src="{{ asset("icons/Waste.svg")}}" alt="">
                                </button>
                            </td>
                        </tr>

                        <form id="delete-form-{{ $konten->id }}" action="{{ route('konten-edukatif.destroy', $konten->id) }}" method="POST" style="display: none;">
                            @csrf
                            @method('DELETE')
                        </form>
                    @endforeach

                </tbody>
            </table>
        </div>
    </div>
    <!-- tabel data-->

<!-- Pagination -->
<div class="flex justify-between border-t-[1px] bg-color-8 border-color-4 p-3">
    <span class="text-sm text-color-2 content-center">
        Menampilkan {{ $kontenEdukatif->firstItem() }} ke {{ $kontenEdukatif->lastItem() }} dari {{ $kontenEdukatif->total() }} data
    </span>

    <nav class="flex items-center gap-x-1" aria-label="Pagination">
        <!-- Tombol Previous -->
        <button type="button" 
            class="min-h-[38px] min-w-[38px] py-2 px-2.5 inline-flex justify-center items-center gap-x-2 text-sm rounded-lg border border-transparent text-color-1 hover:bg-color-5 focus:outline-none focus:bg-color-3 disabled:opacity-50 disabled:pointer-events-none"
            aria-label="Previous" {{ $kontenEdukatif->onFirstPage() ? 'disabled' : '' }}
            onclick="window.location='{{ $kontenEdukatif->previousPageUrl() }}'">
            <svg class="shrink-0 size-3.5" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="m15 18-6-6 6-6"></path>
            </svg>
            <span class="sr-only">Previous</span>
        </button>

        <div class="flex items-center gap-x-1">
            <!-- Tombol Halaman Terendah -->
            <button type="button" 
                class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4 text-color-1 hover:bg-color-5 py-2 px-3 text-sm rounded-lg 
                {{ $kontenEdukatif->currentPage() == 1 ? 'bg-color-3 text-color-5' : 'focus:outline-none focus:bg-color-3' }}" 
                onclick="window.location='{{ $kontenEdukatif->url(1) }}'">1</button>
        
            <!-- Tombol Halaman Sekarang -->
                <button type="button" 
                    class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4  bg-color-3 text-color-5 py-2 px-3 text-sm rounded-lg" 
                    disabled>Halaman {{ $kontenEdukatif->currentPage() }}</button>
        
            <!-- Tombol Halaman Tertinggi -->
            @if ($kontenEdukatif->lastPage() > 1)
                <button type="button" 
                    class="min-h-[38px] min-w-[38px] flex justify-center items-center border border-color-4 text-color-1 hover:bg-color-5 py-2 px-3 text-sm rounded-lg 
                    {{ $kontenEdukatif->currentPage() == $kontenEdukatif->lastPage() ? 'bg-color-3 text-color-5' : 'focus:outline-none focus:bg-color-3' }}" 
                    onclick="window.location='{{ $kontenEdukatif->url($kontenEdukatif->lastPage()) }}'">{{ $kontenEdukatif->lastPage() }}</button>
            @endif
        </div>

        <!-- Tombol Next -->
        <button type="button" 
            class="min-h-[38px] min-w-[38px] py-2 px-2.5 inline-flex justify-center items-center gap-x-2 text-sm rounded-lg border border-transparent text-color-1 hover:bg-color-5 focus:outline-none focus:bg-color-3 disabled:opacity-50 disabled:pointer-events-none"
            aria-label="Next" {{ $kontenEdukatif->hasMorePages() ? '' : 'disabled' }}
            onclick="window.location='{{ $kontenEdukatif->nextPageUrl() }}'">
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