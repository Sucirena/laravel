<?php

namespace App\Http\Controllers;

use App\Models\RiwayatPendidikanTenagaAhli;
use Illuminate\Http\Request;

class RiwayatPendidikanTenagaAhliController extends Controller
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
        $validatedData = $request->validate([
            'id_tenaga_ahli' => 'required|exists:tenaga_ahli,id',
            'keterangan' => 'required|string|max:255',
        ]);

        $riwayatPendidikan = RiwayatPendidikanTenagaAhli::create([
            'id_tenaga_ahli' => $validatedData['id_tenaga_ahli'],
            'keterangan' => $validatedData['keterangan'],
        ]);

        if ($riwayatPendidikan) {
            return redirect()->back()->with('success', 'Data riwayat pendidikan tenaga ahli berhasil ditambahkan!');
        } else {
            return redirect()->back()->with('error', 'Data riwayat pendidikan tenaga ahli gagal ditambahkan!');
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
    public function destroy(string $id)
    {
        $riwayatPendidikan = RiwayatPendidikanTenagaAhli::findOrFail($id);

        $riwayatPendidikanDeleted = $riwayatPendidikan->delete();

        if ($riwayatPendidikanDeleted) {
            return redirect()->back()->with('success', 'Data riwayat pendidikan tenaga ahli berhasil dihapus!');
        } else {
            return redirect()->back()->with('error', 'Data riwayat pendidikan tenaga ahli gagal dihapus!');
        }
    }
}
