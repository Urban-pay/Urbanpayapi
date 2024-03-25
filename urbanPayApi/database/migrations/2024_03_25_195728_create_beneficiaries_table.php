<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('beneficiaries', function (Blueprint $table) {
            $table->id();
            $table->string('user_id');
            $table->string('wallet_id');
            $table->string('transaction_id');
            $table->string('reference');
            $table->string('bank_code');
            $table->string('bank_name');
            $table->string('account_number');
            $table->string('account_name');
            $table->string('urbanPayTag')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('beneficiaries');
    }
};
