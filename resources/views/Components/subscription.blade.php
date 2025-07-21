<input type="checkbox" id="membership" class="modal-toggle" />
<div class="modal select-none" role="dialog">
    <div class="modal-box bg-white border border-gray-200 rounded-lg shadow-lg relative">
        <!-- Tombol Tutup -->
        <label for="membership" class="btn btn-sm btn-circle btn-ghost absolute right-4 top-4">✕</label>

        <!-- Header Modal -->
        <div class="text-center">
            <h5 class="mb-2 text-2xl font-bold text-gray-800">{{ $subscriptionPlan ? $subscriptionPlan->name : '' }}</h5>
        </div>

        <!-- Harga -->
        <div class="flex items-baseline justify-center text-gray-900 my-4">
            <span class="text-3xl font-semibold">
                Rp. 
            </span>
            <span class="text-5xl font-extrabold tracking-tight">
                {{ $subscriptionPlan ? number_format($subscriptionPlan->price, 0, ',', '.') : '' }}
            </span>
            <span class="text-xl font-normal text-gray-500 ml-2">
                /{{ $subscriptionPlan ? $subscriptionPlan->duration : '' }} hari
            </span>
        </div>

        <!-- Fitur-Fitur -->
        <ul role="list" class="space-y-4 my-6">
            <li class="flex items-center">
                <svg class="flex-shrink-0 w-5 h-5 text-color-3" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5Zm3.707 8.207-4 4a1 1 0 0 1-1.414 0l-2-2a1 1 0 0 1 1.414-1.414L9 10.586l3.293-3.293a1 1 0 0 1 1.414 1.414Z"/>
                </svg>
                <span class="text-sm font-normal text-gray-600 ml-3">
                    Chatbot dengan akses berkali lipat.
                </span>
            </li>
            <li class="flex items-center">
                <svg class="flex-shrink-0 w-5 h-5 text-color-3" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5Zm3.707 8.207-4 4a1 1 0 0 1-1.414 0l-2-2a1 1 0 0 1 1.414-1.414L9 10.586l3.293-3.293a1 1 0 0 1 1.414 1.414Z"/>
                </svg>
                <span class="text-sm font-normal text-gray-600 ml-3">
                    Analisis emosi harian dari jurnal.
                </span>
            </li>
            <li class="flex items-center">
                <svg class="flex-shrink-0 w-5 h-5 text-color-3" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5Zm3.707 8.207-4 4a1 1 0 0 1-1.414 0l-2-2a1 1 0 0 1 1.414-1.414L9 10.586l3.293-3.293a1 1 0 0 1 1.414 1.414Z"/>
                </svg>
                <span class="text-sm font-normal text-gray-600 ml-3">
                    Forum diskusi online eksklusif.
                </span>
            </li>
            <li class="flex items-center">
                <svg class="flex-shrink-0 w-5 h-5 text-color-3" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5Zm3.707 8.207-4 4a1 1 0 0 1-1.414 0l-2-2a1 1 0 0 1 1.414-1.414L9 10.586l3.293-3.293a1 1 0 0 1 1.414 1.414Z"/>
                </svg>
                <span class="text-sm font-normal text-gray-600 ml-3">
                    Dukungan teknis prioritas.
                </span>
            </li>
        </ul>

        <!-- Tombol Berlangganan -->
        <button type="button" id="subscribe" class="btn text-white bg-color-2 hover:bg-color-1  font-medium rounded-lg text-lg px-5 py-3 inline-flex justify-center w-full transition duration-300">
            Berlangganan
        </button>
    </div>
    <label class="modal-backdrop" for="membership">Close</label>
</div>
