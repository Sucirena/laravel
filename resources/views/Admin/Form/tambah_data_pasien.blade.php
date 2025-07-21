@extends('layouts.main_admin')


@section('main')

<div class="w-full p-5 rounded-2xl">

    <a href="/super-admin/user-pasien" class="btn btn-sm bg-color-3 text-color-putih hover:bg-opacity-75 border-0">
        <img class="w-6 h-6" src="{{ asset("icons/back.svg")}}" alt="">
        Kembali
    </a>

    <h1 class="font-bold text-3xl text-center">Tambah Data Pasien</h1>
    <div class="pt-10 p-10">

        <form action="{{ route('user-pasien.store') }}" method="post" enctype="multipart/form-data">
            @csrf
            @method('POST')

            <input type="hidden" name="role" value="pasien">

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Email</span>
                <input type="email" name="email" placeholder="Masukkan email Anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('email')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Password</span>
                <input type="password" name="password" placeholder="Masukkan password Anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('password')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror
            
            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Nama</span>
                <input type="text" name="nama" placeholder="Masukkan nama lengkap Anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('nama')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Jenis Kelamin</span>
                <select name="jenis_kelamin" class="select select-bordered w-full  outline outline-1 outline-color-5 bg-color-6 rounded-lg">
                    <option disabled selected>Pilih jenis kelamin</option>
                    <option value="laki laki">Laki - Laki</option>
                    <option value="perempuan">Perempuan</option>
                </select>
            </label>
            @error('jenis_kelamin')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Tanggal Lahir</span>
                <input type="date" name="tanggal_lahir" placeholder="Type here" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('tanggal_lahir')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full pt-5">
                <div class="label">
                    <span class="label-text font-medium text-base">Foto Profil</span>
                </div>
                <input type="file" name="foto_profil" class="file:bg-color-3 file:text-white file:text-sm file:border-none file:h-[3rem] file:mr-4 file:px-4 file:rounded-l-lg file:font-semibold file:uppercase border border-color-5 rounded-lg w-full bg-color-6">
            </label>
            @error('foto_profil')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <label class="form-control w-full mt-5">
                <span class="label-text font-medium text-base pb-1">Deskripsi Diri</span>
                <input type="text" name="deskripsi_diri" placeholder="Masukkan deskripsi diri" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('deskripsi_diri')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror

            <div class="flex justify-center items-center mt-5">
                <button class="btn bg-color-3 text-white w-48">Tambah</button>
            </div>

        </form>
    </div>
</div>

@endsection