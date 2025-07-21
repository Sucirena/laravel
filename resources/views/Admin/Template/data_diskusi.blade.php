@extends('layouts.main_admin2')

@section('main')

<div class="w-full p-5 rounded-2xl">

    <a href="/content-admin/diskusi" class="btn btn-sm bg-color-3 text-color-putih hover:bg-opacity-75 border-0">
        <img class="w-6 h-6" src="{{ asset("icons/back.svg")}}" alt="">
        Kembali
    </a>

    <h1 class="font-bold text-3xl text-center">Detail Data Diskusi</h1>

    <div class="p-10">

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Judul</span>
            <input readonly value="{{ $diskusi->judul }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Isi</span>
            <input readonly value="{{ $diskusi->isi }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Perilis</span>
            <input readonly value="{{ $diskusi->pasien->user->email }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

        <!-- Looping untuk Menampilkan Semua Gambar dalam Diskusi -->
        <div class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Gambar Diskusi</span>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 mt-3">
                @foreach ($diskusi->gambarDiskusi as $gambar)
                    <div class="w-full h-40 overflow-hidden rounded-lg shadow-lg">
                        <img src="{{ asset('storage/' . $gambar->gambar) }}" alt="Gambar Diskusi" class="w-full h-full object-cover">
                    </div>
                @endforeach
            </div>
        </div> 

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Tanggal Dibuat</span>
            <input readonly value="{{ $diskusi->created_at->format('d M Y, H:i') }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

        <label class="form-control w-full pt-5">
            <span class="label-text font-medium text-base pb-1">Terakhir Update</span>
            <input readonly value="{{ $diskusi->updated_at->format('d M Y, H:i') }}" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
        </label>

    </div>
</div>
@endsection
