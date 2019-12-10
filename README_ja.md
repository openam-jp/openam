# OpenAM (OpenAM コンソーシアム版)

OpenAM は認証、認可、エンタイトルメント、およびフェデレーション機能を提供する「オールインワン」アクセス管理ソリューションです。

## ドキュメント

このプロジェクトは [GitHub wiki ページ][github_wiki]でドキュメントを提供します。

## OpenAM アプリケーションの取得

OpenAM WAR ファイルは [GitHub releases ページ][github_releases]から入手できます。

## ソースコードからのビルド

### 前提条件

ソフトウェア           | 必要なバージョン
---------------------- | ----------------
OpenJDK                | 1.8 以上
Maven                  | 3.1.0 以上
Git                    | 1.7.6 以上

### ビルド

OpenAM のビルドプロセスと依存関係は、Maven で管理されています。

現時点では、OpenAMおよび関連製品はMavenリポジトリに登録されていないため、Maven ローカルリポジトリができるまではすべてのプロジェクトをビルドする必要があります。

以下のプロジェクトをチェックアウトし、`mvn install` を順番に実行してください。

* [forgerock-parent](https://github.com/openam-jp/forgerock-parent)
* [forgerock-bom](https://github.com/openam-jp/forgerock-bom)
* [forgerock-build-tools](https://github.com/openam-jp/forgerock-build-tools)
* [forgerock-i18n-framework](https://github.com/openam-jp/forgerock-i18n-framework)
* [forgerock-guice](https://github.com/openam-jp/forgerock-guice)
* [forgerock-ui](https://github.com/openam-jp/forgerock-ui)
* [forgerock-guava](https://github.com/openam-jp/forgerock-guava)
* [forgerock-commons](https://github.com/openam-jp/forgerock-commons)
* [forgerock-persistit](https://github.com/openam-jp/forgerock-persistit)
* [forgerock-bloomfilter](https://github.com/openam-jp/forgerock-bloomfilter)
* [opendj-sdk](https://github.com/openam-jp/opendj-sdk)
* [opendj](https://github.com/openam-jp/opendj)
* [openam](https://github.com/openam-jp/openam)

最後に、`openam/openam-server/target` にバイナリが作成されます。ファイル名の形式は `OpenAM-<バージョン>.war` です。

## コントリビューション

このプロジェクトはあなたのコントリビューションを歓迎します。

バグを見つけたり、改善のアイデアをお持ちの場合は、最初のステップとして [Issue][github_issues] をオープンしてください。
ただし、セキュリティ上の問題が含まれている場合は、[Issue][github_issues] をオープンせずに[ご連絡ください][mail_openam_dev]。

## ライセンス

このプロジェクトは、Common Development and Distribution License（CDDL）でライセンスされています。

## 謝辞

* Sun Microsystems.
* ForgeRock.
* The good things in life.

[mail_openam_dev]: mailto:openam-dev@OpenAM.jp
[github_issues]: https://github.com/openam-jp/openam/issues
[github_wiki]: https://github.com/openam-jp/openam/wiki
[github_releases]: https://github.com/openam-jp/openam/releases

