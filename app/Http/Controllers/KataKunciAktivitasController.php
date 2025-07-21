<?php

namespace App\Http\Controllers;

use App\Models\KataKunciAktivitasPositif;
use Illuminate\Http\Request;

class KataKunciAktivitasController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(): void
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
            $validated = $request->validate([
                'id_aktivitas' => 'required|exists:aktivitas_positif,id',
                'kata_kunci' => 'required|string|min:3|max:255',
            ]);

            KataKunciAktivitasPositif::create([
                'id_aktivitas' => $validated['id_aktivitas'],
                'nama' => $validated['kata_kunci'],
            ]);

            return redirect()->back()->with('success', 'Kata kunci berhasil ditambahkan!');
        } catch (\Exception $e) {
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
            $kataKunci = KataKunciAktivitasPositif::findOrFail($id);
            
            $kataKunci->delete();

            return redirect()->back()->with('success', 'Kata kunci berhasil dihapus!');
        } catch (\Exception $e) {
            return redirect()->back()->with('error', 'Gagal menghapus kata kunci! Pesan error: ' . $e->getMessage());
        }
    }
}
