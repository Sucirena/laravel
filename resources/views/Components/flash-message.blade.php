
@if(session()->has('success'))
<div class="absolute top-[100px] left-1/2 transform -translate-x-1/2 -translate-y-1 z-40">
    <div role="alert" id="toast" class="alert alert-success flex col-span-9 mb-5">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span class="text-xs">{{ session('success')}}</span>
        <button id="close-toast" class=" text-lg font-semibold text-black hover:text-gray-700 focus:outline-none">
            ✕
        </button>
    </div>
</div>
@endif

@if(session()->has('error'))
<div class="absolute top-[100px] left-1/2 transform -translate-x-1/2 -translate-y-1 z-40">
    <div role="alert" id="toast" class="alert alert-error col-span-9 mb-5">
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 shrink-0 stroke-current" fill="none" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span>{{ session('error')}}</span>
        <button id="close-toast" class="ml-4 text-lg font-semibold text-black hover:text-gray-700 focus:outline-none">
            ✕
        </button>
    </div>
</div>
@endif

<script>
    document.addEventListener('DOMContentLoaded', function () {
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
    });
</script>
