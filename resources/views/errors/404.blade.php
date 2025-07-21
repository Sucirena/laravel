<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    @vite(['resources/css/app.css','resources/js/app.js'])
    <title>404 Error</title>
    <link rel="icon" type="image/svg+xml" href=" {{ asset('images/logo-icon.svg') }} ">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&family=Space+Grotesk:wght@300..700&display=swap" rel="stylesheet">
</head>
<body class="font-poppins text-color-1">

    <header class="sticky top-0 z-[999]">
        <div class="flex flex-row justify-between h-20 py-[15px] px-[50px] bg-color-8  border-b border-color-4 ">
            <a href="
            @auth
                @if (Auth::user()->role === 'admin' && Auth::user()->admin->admin_role === 'superadmin')
                    /super-admin
                @elseif (Auth::user()->role === 'admin' && Auth::user()->admin->admin_role === 'content admin')
                    /content-admin
                @elseif (Auth::user()->role === 'tenaga ahli')
                    /tenaga-ahli
                @else
                    /
                @endif
            @else
                /
            @endauth
            " class="flex flex-row">
                <img class="h-[50px] w-[50px] me-[15px]" src=" {{ asset('images/logo-dark-blue.svg') }} " alt="SupporT-een Logo">
                <span class="my-auto text-[2rem]">SupporT-een</span>
            </a>

            <div class="flex items-center justify-center select-none" id="flash-message-place">
                @include('Components.flash-message')
                @auth
                    @if(Auth::user()->role === 'pasien' && !Auth::user()->isPremium() || Auth::user()->isPremium() && Auth::user()->premiumEndingSoon())
                        <div id="card" class="absolute -top-[310px] left-1/2 transform -translate-x-1/2 -translate-y-1 bg-color-1 shadow-lg rounded-lg p-3 max-w-[500px] text-center transition-all duration-300 text-color-putih hover:translate-y-80">
                            <!-- Konten Card -->
                            <!-- Badge atau Tagline -->
                            <div class="flex justify-center mb-4">
                                <span class="px-3 py-1 text-xs font-bold uppercase bg-color-3 text-color-putih rounded-full shadow-sm">
                                    Spesial Premium
                                </span>
                            </div>
                            <p class="mb-4">
                                Nikmati fitur eksklusif kami dengan berlangganan. Dapatkan akses premium hari ini dan tingkatkan pengalaman Anda!
                            </p>
                            <div class="flex justify-center mb-6">
                                <svg class="flex-shrink-0 w-20 h-20 text-color-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 20 20">
                                    <path d="M10 .5a9.5 9.5 0 1 0 9.5 9.5A9.51 9.51 0 0 0 10 .5Zm3.707 8.207-4 4a1 1 0 0 1-1.414 0l-2-2a1 1 0 0 1 1.414-1.414L9 10.586l3.293-3.293a1 1 0 0 1 1.414 1.414Z"/>
                                </svg>
                            </div>
                            <label for="membership" class="btn w-full py-2 px-4 text-2xl font-bold text-color-1 rounded-lg bg-color-6 hover:bg-color-5 transition duration-300">
                                Berlangganan Sekarang!
                            </label>
                            <div class="divider mb-0"></div>
                            <div class="flex absolute bg-color-1 -bottom-10 left-1/2 transform -translate-x-1/2 px-3 pt-0 pb-1 rounded-lg shadow-lg">
                                <p class="flex font-medium text-3xl items-center">PREM</p>
                                <img class="h-[50px] w-[50px]" src="{{ asset('icons/Guarantee.svg') }}">
                                <p class="flex font-medium text-3xl items-center">UM</p>
                            </div>
                        </div>
                        
                        @include('Components.subscription')
                    @endif
                @endauth
            </div>

        </div>
    </header>

    <div class="min-h-[calc(100vh-80px)] flex w-full bg-color-8">
        <aside class="w-2/5 flex flex-col justify-center items-center">
            <!-- Konten aside -->

            <h1 class="text-[10rem] p-0 font-semibold border-b-4 border-opacity border-color-1 rounded">404</h1>

        </aside>
        <main class="w-3/5 bg-color-8 border-l border-color-4">
            <div class="bg-cover bg-brain-pattern flex flex-col mx-auto p-6 w-full justify-center items-center h-full relative overflow-auto">
                <!-- Konten main -->

                <div class="flex flex-col gap-5 px-10 w-full text-left text-color-1">
                    <h1 class="text-6xl font-semibold">Oops!</h1>
                    <h1 class="text-4xl font-semibold">Maaf, halaman yang anda cari tidak dapat ditemukan</h1>
                    <span class="text-xl">Silahkan tekan tombol berikut untuk kembali</span>
                    <a href="
                    @auth
                        @if (Auth::user()->role === 'admin' && Auth::user()->admin->admin_role === 'superadmin')
                            /super-admin
                        @elseif (Auth::user()->role === 'admin' && Auth::user()->admin->admin_role === 'content admin')
                            /content-admin
                        @elseif (Auth::user()->role === 'tenaga ahli')
                            /tenaga-ahli
                        @else
                            /
                        @endif
                    @else
                        /
                    @endauth
                    " class="btn bg-color-4 text-color-putih hover:bg-color-2 border-0">
                        Kembali
                    </a>
                </div>

            </div>
        </main>

    </div>

    <footer class="text-color-8">
        <div class="grid grid-cols-4 bg-color-1 h-fit px-[150px]">

            <div class="col-span-4  w-full mx-auto text-center mt-auto">
                <span class="text-xs">&copy; <?php echo date("Y"); ?> SupporT-een</span>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>

</body>
</html>