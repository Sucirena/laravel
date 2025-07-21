@extends('layouts.main_admin2')

@section('main')

<!-- halaman tambah data konten edukatif -->
<div class="w-full p-5 rounded-2xl">

    <a href="/content-admin/konten-edukatif" class="btn btn-sm bg-color-3 text-color-putih hover:bg-opacity-75 border-0">
        <img class="w-6 h-6" src="{{ asset("icons/back.svg")}}" alt="">
        Kembali
    </a>

    <h1 class="font-bold text-3xl text-center">Tambah Data Konten Edukatif</h1>

    <!-- form untuk menambah data konten edukatif-->
    <form action="{{ route('konten-edukatif.store') }}" method="POST" enctype="multipart/form-data">
        @csrf
        @method('POST')

        <div class="flex flex-col gap-y-5 pt-10 p-10">
    
            <!-- judul -->
            <label class="form-control w-full">
                <span class="label-text font-medium text-base pb-1">Judul</span>
                <input type="text" name="judul" placeholder="Masukkan judul anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('judul')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror
            <!-- judul -->
    
            <!-- tipe konten -->
            <label class="form-control w-full">
                <span class="label-text font-medium text-base pb-1">Tipe</span>
                <select name="tipe" id="tipe" class="select select-bordered w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg">
                    <option disabled selected>Pilih tipe konten</option>
                    <option value="artikel">Artikel</option>
                    <option value="video">Video</option>
                </select>
            </label>
            @error('tipe')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror
            <!-- tipe konten -->
    
            <!-- thumbnail -->
            <label class="form-control w-full">
                <div class="label">
                    <span class="label-text font-medium text-base">Thumbnail</span>
                </div>
                <input type="file" name="thumbnail" class="file:bg-color-3 file:text-white file:text-sm file:border-none file:h-[3rem] file:mr-4 file:px-4 file:rounded-l-lg file:font-semibold file:uppercase border border-color-5 rounded-lg w-full bg-color-6">
            </label>
            @error('thumbnail')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror
            <!-- thumbnail -->
    
            <!-- kata kunci -->
            <label class="form-control w-full">
                <span class="label-text font-medium text-base pb-1">Kata Kunci</span>
                <input type="text" name="kata_kunci" placeholder="Kata kunci" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('kata_kunci')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror
            <!-- kata kunci -->
            
            <!-- Sumber -->
            <label class="form-control w-full">
                <span class="label-text font-medium text-base pb-1">Sumber</span>
                <input type="text" name="sumber" placeholder="Masukkan link youtube" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('sumber')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror
            <!-- Sumber -->
            
            <!-- link youtube -->
            <label class="form-control w-full" id="link_youtube_div" style="display:none;">
                <span class="label-text font-medium text-base pb-1">Link Youtube</span>
                <input type="text" name="link_youtube" placeholder="Masukkan link youtube" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
            </label>
            @error('link_youtube')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror
            <!-- link youtube -->
    
            <!-- isi artikel -->
            <label class="form-control w-full" id="isi_artikel_div" style="display:none;">
                <span class="label-text font-medium text-base pb-1">Isi Artikel</span>
                <textarea name="isi_artikel" class="textarea textarea-bordered h-40 outline outline-1 outline-color-5 bg-color-6 rounded-lg w-full" placeholder="Deskripsi"></textarea>
            </label>
            @error('isi_artikel')
                <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
            @enderror
            <!-- isi artikel -->
    
            <!-- tombol tambah -->
            <label class="flex justify-center items-center pt-5">
                <button type="submit" class="btn bg-color-3 text-white w-48">Tambah</button>
            </label>
            <!-- tombol tambah -->
        </div>
    </form>    
    
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const tipeKontenSelect = document.getElementById('tipe');
        const isiArtikelDiv = document.getElementById('isi_artikel_div');
        const linkYoutubeDiv = document.getElementById('link_youtube_div');
        const isiArtikelInput = document.querySelector('[name="isi_artikel"]');
        const linkYoutubeInput = document.querySelector('[name="link_youtube"]');

        // Fungsi untuk mengupdate tampilan berdasarkan tipe konten yang dipilih
        function updateFormFields() {
            const tipeKonten = tipeKontenSelect.value;

            if (tipeKonten === 'artikel') {
                // Tampilkan input Isi Artikel, sembunyikan Link Youtube
                isiArtikelDiv.style.display = 'block';
                linkYoutubeDiv.style.display = 'none';
                linkYoutubeInput.disabled = true;
                isiArtikelInput.disabled = false;
            } else if (tipeKonten === 'video') {
                // Tampilkan input Link Youtube, sembunyikan Isi Artikel
                linkYoutubeDiv.style.display = 'block';
                isiArtikelDiv.style.display = 'none';
                isiArtikelInput.disabled = true;
                linkYoutubeInput.disabled = false;
            }
        }

        // Panggil fungsi awal untuk menyesuaikan tampilan berdasarkan pilihan default
        updateFormFields();

        // Tambahkan event listener untuk perubahan tipe konten
        tipeKontenSelect.addEventListener('change', updateFormFields);
    });

</script>
@endsection