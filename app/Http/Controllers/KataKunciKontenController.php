<?php

namespace App\Http\Controllers;

use App\Models\KataKunciKonten;
use Illuminate\Http\Request;

class KataKunciKontenController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        try {
            // Validasi input kata kunci
            $validated = $request->validate([
                'id_konten' => 'required|exists:konten_edukatif,id', // Memastikan konten yang dituju ada
                'kata_kunci' => 'required|string|min:3|max:255', // Validasi kata kunci
            ]);

            // Menyimpan data kata kunci
            KataKunciKonten::create([
                'id_konten' => $validated['id_konten'],
                'nama' => $validated['kata_kunci'],
            ]);

            // Kembali dengan pesan sukses
            return redirect()->back()->with('success', 'Kata kunci berhasil ditambahkan!');
        } catch (\Exception $e) {
            // Jika terjadi error
            return redirect()->back()->with('error', 'Gagal menambahkan kata kunci! Pesan error: ' . $e->getMessage());
        }
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy($id)
    {
        try {
            // Mencari kata kunci konten berdasarkan ID
            $kataKunciKonten = KataKunciKonten::findOrFail($id);
            
            // Menghapus kata kunci konten
            $kataKunciKonten->delete();

            // Kembali dengan pesan sukses
            return redirect()->back()->with('success', 'Kata kunci berhasil dihapus!');
        } catch (\Exception $e) {
            // Jika terjadi error
            return redirect()->back()->with('error', 'Gagal menghapus kata kunci! Pesan error: ' . $e->getMessage());
        }
    }
}
