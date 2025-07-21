<!-- halaman forum diskusi -->
@extends('layouts.main')

@section('aside')

<div class="flex flex-col mx-auto w-full h-full pt-9 px-8 xl:px-12 gap-6">
    <a href="{{ route('forum-diskusi.create') }}" class="btn flex justify-start bg-color-6 hover:bg-color-5 hover:border-color-3 text-base">
        <img src="{{ asset('icons/Plus.svg') }}" alt="Plus">
        Buat Diskusi
    </a>
    <h1 class="text-4xl font-bold text-color-1 text-start">Diskusi Anda</h1>
    <div class="flex flex-col w-full h-full gap-4">

        @include('pasien.components.card_list')

    </div>
</div>

@endsection

@section('main')

<!-- offcanvas -->
<div 
        id="hs-offcanvas-example" 
        class="hs-overlay hidden fixed inset-y-0 left-0 transform -translate-x-full transition-all duration-500 ease-in-out z-[80] bg-white shadow-lg max-w-sm w-full lg:hidden" 
        role="dialog" 
        tabindex="-1" 
        aria-labelledby="hs-offcanvas-example-label">
        
        <!-- Header Offcanvas -->
        <div class="flex justify-between items-center py-3 px-4 border-b">
            <!-- logo -->
            <a href="{{ Auth::check() && Auth::user()->role === 'tenaga ahli' ? '/tenaga-ahli' : '/' }}" class="flex flex-row items-center">
                <img class="size-[1.875rem] me-0.5 md:size-12 xl:size-[3.125rem] md:me-2 xl:me-[0.938rem]" src=" {{ asset('images/logo-dark-blue.svg') }} " alt="SupporT-een Logo">
                <span class="my-auto text-xs md:text-2xl xl:text-[2rem]">SupporT-een</span>
            </a>

            <!-- tombol close -->
            <button 
                type="button" 
                class="inline-flex justify-center items-center rounded-full border bg-gray-100 text-gray-800 hover:bg-gray-200 focus:outline-none focus:bg-gray-200" 
                aria-label="Close" 
                data-hs-overlay="#hs-offcanvas-example">
                <span class="sr-only">Close</span>
                <svg class="w-6 h-6" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 6 6 18M6 6l12 12"></path>
                </svg>
            </button>
        </div>

        <!-- Content Offcanvas -->
        <div class="p-4">

            <!-- tombol tambah diskusi -->
            <a href="{{ route('forum-diskusi.create') }}" class="btn flex justify-start bg-color-6 hover:bg-color-5 hover:border-color-3 text-base">
                <img src="{{ asset('icons/Plus.svg') }}" alt="Plus">
                Buat Diskusi
            </a>

            <h1 class="text-2xl xl:text-4xl font-bold text-color-1 w-full mt-4">Diskusi Anda</h1>
                
                <div class="flex flex-col w-full h-full gap-4 mt-4 max-h-[calc(100vh-270px)] overflow-y-auto overflow-x-hidden">

                    @include('pasien.components.card_list')

                </div>

        </div>
        <!-- End Content Offcanvas -->
    </div>
    <!-- End Offcanvas -->

    @foreach ($diskusiList as $diskusi)
            <!-- Modal Konfirmasi Hapus Diskusi -->
            <dialog id="delete-diskusi-modal-{{ $diskusi->id }}" class="modal">
                <div class="modal-box bg-color-8">
                    <h3 class="text-lg font-bold">Konfirmasi Penghapusan</h3>
                    <p>Apakah Anda yakin ingin menghapus diskusi ini?</p>
                    <div class="modal-action">
                        <!-- Tombol Batal -->
                        <button type="button" class="btn bg-color-7 hover:bg-color-8" onclick="this.closest('dialog').close()">Batal</button>
                        
                        <form method="POST" action="{{ route('forum-diskusi.destroy', $diskusi->id) }}">
                            @csrf
                            @method('DELETE')
                            <button type="submit" class="btn bg-red-500 text-white hover:bg-red-700">Hapus</button>
                        </form>
                        
                    </div>
                </div>
            </dialog>
            @endforeach

<!-- tampilan edit diskusi -->
<div class="flex flex-col w-full h-full">
    <div class="bg-color-8 p-8 border-[1px] border-color-4 rounded-2xl">
        <a href="/forum" class="btn btn-sm bg-color-3 text-color-putih hover:bg-opacity-75 border-0">
            <img class="w-6 h-6" src="{{ asset('icons/back.svg') }}" alt="">
            Kembali
        </a>
        <h1 class="font-bold text-2xl md:text-3xl text-center mt-6">Edit Data Diskusi</h1>
        <div class="p-5">

            <form action="{{ route('forum-diskusi.update', $diskusi->id) }}" method="POST" enctype="multipart/form-data">
                @csrf
                @method('PATCH')

                <!-- Input Judul -->
                <label class="form-control w-full mt-5">
                    <span class="label-text font-medium text-base pb-1">Judul</span>
                    <input type="text" name="judul" value="{{ $diskusi->judul }}" placeholder="Masukkan judul anda" class="input input-bordered input-md w-full outline outline-1 outline-color-5 bg-color-6 rounded-lg" />
                    @error('judul')
                        <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
                    @enderror
                </label>

                @if ($diskusi->gambarDiskusi->count() > 0)
                <!-- Gambar yang sudah ada -->
                <div class="form-control w-full mt-5">
                    <div class="label">
                        <span class="label-text font-medium text-base">Gambar Tersimpan</span>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-4">

                        @foreach ($diskusi->gambarDiskusi as $gambar)
                            <div class="relative border border-color-5 rounded-lg">
                                <img class="rounded-lg object-cover w-full h-40"
                                    src="{{ asset('storage/' . $gambar->gambar) }}" alt="Gambar Diskusi">
                                <button type="button" class="absolute top-2 right-2 bg-red-500 text-white rounded-full size-8 text-xs"
                                    onclick="document.getElementById('delete-gambar-modal-{{ $gambar->id }}').showModal();">
                                    ✕
                                </button>
                            </div>
                        @endforeach

                    </div>
                </div>
                @endif

                <!-- Input Gambar -->
                <label class="form-control w-full mt-5">
                    <div class="label">
                        <span class="label-text font-medium text-base">Gambar</span>
                    </div>
                    <input type="file" name="gambar[]" id="gambar-input" multiple
                        accept="image/*"
                        class="file:bg-color-3 file:text-white file:text-sm file:border-none file:h-12 file:mr-4 file:px-4 file:rounded-l-lg file:font-semibold file:uppercase border border-color-5 rounded-lg w-full bg-color-6">
                    @error('gambar[]')
                        <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
                    @enderror
                </label>

                <!-- Preview Gambar -->
                <div id="preview-container" 
                    class="mt-5 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-4">
                </div>

                <!-- Input Isi -->
                <label class="form-control w-full mt-5">
                    <span class="label-text font-medium text-base pb-1">Isi</span>
                    <textarea name="isi" class="textarea textarea-bordered h-40 outline outline-1 outline-color-5 bg-color-6 rounded-lg"
                        placeholder="Isi diskusi">{{ old('isi', $diskusi->isi) }}</textarea>
                    @error('isi')
                        <div class="text-red-500 text-sm mt-1">{{ $message }}</div>
                    @enderror
                    </label>

                <!-- Tombol Tambah -->
                <label class="flex justify-center items-center mt-5">
                    <button type="submit" class="btn bg-color-3 text-white w-48">Perbarui</button>
                </label>
            </form>

        </div>
    </div>
</div>
<!-- tampilan edit diskusi -->

@foreach ($diskusi->gambarDiskusi as $gambar)
    <dialog id="delete-gambar-modal-{{ $gambar->id }}" class="modal">
        <div class="modal-box bg-color-8">
            <h3 class="text-lg font-bold">Konfirmasi Penghapusan</h3>
            <p>Apakah Anda yakin ingin menghapus gambar ini?</p>
            <div class="modal-action">
                <button type="button" class="btn bg-color-7 hover:bg-color-8" onclick="this.closest('dialog').close()">Batal</button>

                <form method="POST" action="{{ route('gambar-diskusi.destroy', $gambar->id) }}">
                    @csrf
                    @method('DELETE')
                    <button type="submit" class="btn bg-red-500 text-white hover:bg-red-700">Hapus</button>
                </form>

            </div>
        </div>
    </dialog>
@endforeach

<script>
    document.addEventListener('DOMContentLoaded', () => {
        const gambarInput = document.getElementById('gambar-input');
        const previewContainer = document.getElementById('preview-container');
        const flashMessagePlace = document.getElementById('flash-message-place');

        // Hitung gambar yang sudah ada
        const existingImagesCount = {{ $diskusi->gambarDiskusi->count() }};
        const maxImagesCount = 5;

        gambarInput.addEventListener('change', function (event) {
            const files = event.target.files;

            // Validasi jumlah total file (termasuk yang sudah ada)
            const currentFilesCount = document.querySelectorAll('.hidden-file-input').length + existingImagesCount;
            if (currentFilesCount + files.length > maxImagesCount) {
                flashMessagePlace.insertAdjacentHTML('beforeend', `
                    <div role="alert" id="toast" class="absolute top-[100px] left-1/2 transform -translate-x-1/2 -translate-y-1 z-40">
                        <div class="alert alert-error col-span-9 mb-5">
                            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <span>Maksimal ${maxImagesCount} gambar dalam 1 diskusi!</span>
                            <button id="close-toast" class="ml-4 text-lg font-semibold text-black hover:text-gray-700 focus:outline-none">
                                ✕
                            </button>
                        </div>
                    </div>
                `);

                initializeToast();
                
                gambarInput.value = ''; // Reset input file
                return;
            }

            Array.from(files).forEach((file) => {
                const reader = new FileReader();

                reader.onload = function (e) {
                    // Tambahkan preview gambar
                    const previewCard = document.createElement('div');
                    previewCard.classList.add('relative', 'w-full', 'h-40', 'border', 'border-color-5', 'rounded-xl', 'overflow-hidden');

                    previewCard.innerHTML = `
                        <img src="${e.target.result}" alt="Preview Gambar" class="w-full h-full object-cover">
                        <button type="button" class="absolute top-2 right-2 bg-red-500 text-white rounded-full p-1 text-xs"
                            onclick="removeImage(this)">✕</button>
                    `;

                    // Tambahkan file input tersembunyi
                    const hiddenInput = document.createElement('input');
                    hiddenInput.type = 'file';
                    hiddenInput.name = 'gambar[]';
                    hiddenInput.classList.add('hidden-file-input');
                    hiddenInput.files = createFileList([file]);

                    previewCard.appendChild(hiddenInput);

                    previewContainer.appendChild(previewCard);
                };

                reader.readAsDataURL(file);
            });

            // Reset file input utama
            gambarInput.value = '';
        });

        // Fungsi untuk menghapus gambar dan input terkait
        window.removeImage = (button) => {
            button.parentElement.remove();
        };

        function createFileList(files) {
            const dataTransfer = new DataTransfer();
            files.forEach(file => dataTransfer.items.add(file));
            return dataTransfer.files;
        }

        // Fungsi untuk menginisialisasi toast
        function initializeToast() {
            const toastElement = document.getElementById('toast');
            const closeButton = document.getElementById('close-toast');
            const toastDuration = 3000; // Durasi tampil dalam milidetik (3 detik)

            if (toastElement) {
                // Animasi fade-in
                toastElement.style.opacity = '0';
                toastElement.style.transition = 'opacity 0.5s ease';
                setTimeout(() => {
                    toastElement.style.opacity = '1';
                }, 10); // Delay untuk memastikan elemen di-render

                // Timer untuk menghilangkan toast
                setTimeout(() => {
                    // Animasi fade-out
                    toastElement.style.opacity = '0';
                    setTimeout(() => {
                        toastElement.remove(); // Hapus elemen setelah animasi selesai
                    }, 500); // Waktu animasi fade-out (0.5 detik)
                }, toastDuration);
            }

            if (closeButton) {
                // Tombol close
                closeButton.addEventListener('click', function () {
                    toastElement.style.opacity = '0'; // Animasi fade-out
                    setTimeout(() => {
                        toastElement.remove(); // Hapus elemen setelah animasi selesai
                    }, 500); // Waktu animasi fade-out
                });
            }
        }
    });
</script>

@endsection