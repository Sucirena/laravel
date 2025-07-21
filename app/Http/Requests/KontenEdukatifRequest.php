<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class KontenEdukatifRequest extends FormRequest
{
    /**
     * Tentukan apakah pengguna memiliki izin untuk membuat permintaan ini.
     *
     * @return bool
     */
    public function authorize()
    {
        // Mengizinkan semua pengguna untuk mengakses request ini (ubah jika perlu)
        return true;
    }

    /**
     * Tentukan aturan validasi untuk permintaan ini.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'judul' => 'required|string|max:255',
            'tipe' => 'required|in:artikel,video',
            'thumbnail' => $this->isMethod('post') 
                ? 'required|image|mimes:jpeg,png,jpg,gif|max:2048' // Required saat store
                : 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048',  // Nullable saat update
            'kata_kunci' => 'nullable|string',
            'sumber' => 'required|string',
            'link_youtube' => [
                'nullable', // Boleh kosong
                'url',      // Harus berupa URL
                'regex:/^(?:https?:\/\/)?(?:www\.)?(?:youtu\.be\/|youtube\.com\/(?:embed\/|v\/|playlist\?|watch\?v=|watch\?.+(?:&|&#38;)?v=))([a-zA-Z0-9\-_]{11})?(?:(?:\?|&|&#38;)index=((?:\d){1,3}))?(?:(?:\?|&|&#38;)?list=([a-zA-Z\-_0-9]{34}))?(?:\S+)?$/', // Validasi link YouTube
            ],
            // 'link_youtube' => 'nullable|url|regex:/^(?:https?:\/\/)?(?:www\.)?(?:youtu\.be\/|youtube\.com\/(?:embed\/|v\/|playlist\?|watch\?v=|watch\?.+(?:&|&#38;)?v=))([a-zA-Z0-9\-_]{11})?(?:(?:\?|&|&#38;)index=((?:\d){1,3}))?(?:(?:\?|&|&#38;)?list=([a-zA-Z\-_0-9]{34}))?(?:\S+)?$/', // Validasi URL untuk video
            'isi_artikel' => 'nullable|string', // Validasi artikel
        ];
    }

    /**
     * Tentukan pesan validasi khusus.
     *
     * @return array
     */
    public function messages()
    {
        return [
            'judul.required' => 'Judul konten harus diisi.',
            'tipe.required' => 'Tipe konten harus dipilih.',
            'thumbnail.required' => 'Thumbnail konten harus diupload.',
            'thumbnail.image' => 'File thumbnail harus berupa gambar.',
            'thumbnail.mimes' => 'Thumbnail hanya boleh berupa gambar dengan ekstensi jpeg, png, jpg, atau gif.',
            'thumbnail.max' => 'Ukuran gambar thumbnail maksimal 2MB.',
            'kata_kunci.string' => 'Kata kunci harus berupa string.',
            'sumber.required' => 'Sumber konten harus diisi.',
            'link_youtube.url' => 'Link Youtube harus berupa URL yang valid.',
            'link_youtube.regex' => 'Link YouTube yang dimasukkan tidak valid. Harap pastikan URL mengarah ke YouTube.',
            'isi_artikel.string' => 'Isi artikel harus berupa teks.',
        ];
    }
}
