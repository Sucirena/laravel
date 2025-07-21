@extends('layouts.main_admin2')

@section('main')

<!-- halaman edit konten edukatif -->
<div class="w-full p-5 rounded-2xl">

    <a href="/content-admin/konten-edukatif" class="btn btn-sm bg-color-3 text-color-putih hover:bg-opacity-75 border-0">
        <img class="w-6 h-6" src="{{ asset("icons/back.svg")}}" alt="">
        Kembali
    </a>

    <div class="pt-10 p-10">
        <h1 class="font-bold text-3xl text-center">Edit Data Konten Edukatif</h1>

        <!-- form edit konten edukatif -->
        <form action="{{ route('konten-edukatif.update', $kontenEdukatif->id) }}" method="POST" enctype="multipart/form-data">
            @csrf
            @method('PATCH')

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Tipe Konten</span>
                <input readonly type="text" name="tipe" value="{{ $kontenEdukatif->tipe }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
                <div class="label">
                    <span class="label-text-alt">*Tipe konten tidak dapat diubah</span>
                </div>
            </label>
            @error('tipe')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror
            
            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Judul</span>
                <input type="text" name="judul" value="{{ $kontenEdukatif->judul }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('judul')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full pt-5">
                <span class="label-text font-medium text-base pb-1">Thumbnail</span>
                <input type="file" name="thumbnail" class="file:bg-color-3 file:text-white file:text-sm file:border-none file:h-[3rem] file:mr-4 file:px-4 file:rounded-l-lg file:font-semibold file:uppercase border border-color-5 rounded-lg w-full bg-color-6" />
            </label>
            @error('thumbnail')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Sumber</span>
                <input type="text" name="sumber" value="{{ $kontenEdukatif->sumber }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('sumber')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <!-- Link Youtube hanya tampil jika tipe adalah video -->
            @if ($kontenEdukatif->tipe == 'video')
                <label class="form-control w-full pt-5">
                    <span class="label-text font-medium text-base pb-1">Link Youtube</span>
                    <input type="url" name="link_youtube" value="{{ $kontenEdukatif->link_youtube }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
                </label>
                @error('link_youtube')
                    <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
                @enderror
            @endif
            <!-- Link Youtube -->

            <!-- Isi Artikel hanya tampil jika tipe adalah artikel -->
            @if ($kontenEdukatif->tipe == 'artikel')
                <label class="form-control w-full mt-5">
                    <span class="label-text font-medium text-base pb-1">Isi Artikel</span>
                    <textarea name="isi_artikel" rows="5" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg">{{ $kontenEdukatif->isi_artikel }}</textarea>
                </label>
                @error('isi_artikel')
                    <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
                @enderror
            @endif
            <!-- Isi Artikel -->

            <label class="flex justify-center items-center pt-10">
                <button class="btn bg-color-3 text-white w-48">Perbarui</button>
            </label>

        </form>
        <div class="divider"></div>

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Kata Kunci</span>

            @foreach ($kontenEdukatif->kataKunci as $key => $kataKunci)
                <div class="flex gap-x-3">
                    <input readonly value="{{ $kataKunci->nama }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg mb-5" />
                    <form action="{{ route('kata-kunci-konten.destroy', $kataKunci->id) }}" method="POST">
                        @csrf
                        @method('DELETE')
                        <button type="submit" class="btn bg-red-100 text-red-500 border-red-500">
                            <img class="w-6 h-6" src="{{ asset('icons/Waste.svg') }}" alt="Delete">
                        </button>
                    </form>
                </div>
            @endforeach

            <form action="{{ route('kata-kunci-konten.store') }}" method="POST">
                @csrf

                <label class="form-control w-full">
                    <input type="hidden" name="id_konten" value="{{ $kontenEdukatif->id }}">
                    <input type="text" name="kata_kunci" placeholder="Masukkan kata kunci" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
                </label>
                @error('kata_kunci')
                    <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
                @enderror

                <div class="flex justify-center items-center mt-5">
                    <button class="btn bg-color-3 text-white w-48">Tambah</button>
                </div>

            </form>
        </label>
    </div>
</div>

@endsection